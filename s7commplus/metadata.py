"""CPU and project metadata helpers ported from S7CommPlusDriver.

Reads identification, cycle time, memory usage and text-container languages
via GetVarSubStreamed / EXPLORE. Plaintext S7-1200 FW2.x sessions use the
old GetVarSubStreamed framing from S7CommPlusDriver PR #25.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Optional, Protocol

from .codec import decode_pvalue_to_bytes, decode_wstring, encode_object_qualifier
from .error import S7ConnectionError, S7ProtocolError
from .protocol import DataType, FunctionCode, Ids, ProtocolVersion
from .vlq import decode_uint32_vlq, decode_uint64_vlq, encode_uint32_vlq


class _MetadataConnection(Protocol):
    """Minimal connection surface used by the metadata helpers."""

    protocol_version: int
    secured_session: bool
    object_qualifier_version: int

    def send_request(
        self, function_code: int, payload: bytes = b"", integrity_tail: int = 4, reassemble: bool = False
    ) -> bytes: ...


@dataclass(frozen=True)
class CpuInfo:
    """PLC identity as reported by CPUProxy / CPUCommon / ASRoot."""

    mlfb: str
    serial: str
    firmware: tuple[int, int, int, int]
    plc_name: Optional[str] = None
    project_name: Optional[str] = None
    version_tia: Optional[tuple[int, int, int, int]] = None
    version2: Optional[tuple[int, int, int, int]] = None

    @property
    def firmware_string(self) -> str:
        return ".".join(str(part) for part in self.firmware)


@dataclass(frozen=True)
class CpuCycleTime:
    """Scan-cycle times in milliseconds."""

    shortest_ms: float
    current_ms: float
    longest_ms: float
    configured_minimum_ms: Optional[float] = None
    configured_maximum_ms: Optional[float] = None


@dataclass(frozen=True)
class CpuMemoryArea:
    """One PLC memory area with total/used byte counts."""

    key: str
    name: str
    total_bytes: int
    used_bytes: int

    @property
    def free_bytes(self) -> int:
        return max(0, self.total_bytes - self.used_bytes)

    @property
    def used_percent(self) -> Optional[float]:
        if self.total_bytes <= 0:
            return None
        return min(100.0, self.used_bytes * 100.0 / self.total_bytes)


@dataclass(frozen=True)
class CpuMemoryUsage:
    """Aggregated CPU memory areas."""

    areas: tuple[CpuMemoryArea, ...] = ()


@dataclass(frozen=True)
class CpuCultureInfo:
    """Language IDs advertised by the PLC text container."""

    language_ids: tuple[int, ...] = ()

    @property
    def primary_language_id(self) -> Optional[int]:
        return self.language_ids[0] if self.language_ids else None


@dataclass(frozen=True)
class _DecodedPValue:
    flags: int
    datatype: int
    raw: bytes


def uses_old_firmware_gvs_framing(connection: _MetadataConnection) -> bool:
    """True for plaintext V1 sessions without SessionKey (e.g. S7-1200 FW2.2)."""
    version = int(getattr(connection.protocol_version, "value", connection.protocol_version))
    return version == ProtocolVersion.V1 and not connection.secured_session


def build_get_var_substreamed_payload(
    object_id: int,
    address: int,
    *,
    old_firmware_framing: bool = False,
    protocol_version: int = ProtocolVersion.V2,
    key_qualifier: int = 0,
    sequence_field: int = 1,
) -> bytes:
    """Build a GetVarSubStreamed request set for one object attribute."""
    payload = struct.pack(">I", object_id)
    payload += bytes([0x20, DataType.UDINT, 0x01])
    payload += encode_uint32_vlq(address)
    if old_firmware_framing:
        # S7-1200 FW2.2 plaintext: fixed KeyQualifier=1, no attribute-list
        # terminator, fixed UInt32 integrity id (typically 0), no fill trailer.
        payload += struct.pack(">I", Ids.OBJECT_QUALIFIER)
        payload += encode_uint32_vlq(Ids.PARENT_RID) + bytes([0x00, DataType.RID]) + struct.pack(">I", 0)
        payload += encode_uint32_vlq(Ids.COMPOSITION_AID) + bytes([0x00, DataType.AID]) + encode_uint32_vlq(0)
        payload += encode_uint32_vlq(Ids.KEY_QUALIFIER) + bytes([0x00, DataType.UDINT]) + struct.pack(">I", 1)
        payload += struct.pack(">I", 0)
        return payload
    payload += encode_object_qualifier(key_qualifier=key_qualifier, protocol_version=protocol_version)
    payload += struct.pack(">H", sequence_field)
    payload += struct.pack(">I", 0)
    return payload


def parse_get_var_substreamed_pvalue(payload: bytes) -> _DecodedPValue:
    """Decode the typed PValue from a GetVarSubStreamed response payload."""
    try:
        return_value, offset = decode_uint64_vlq(payload, 0)
        if return_value != 0:
            raise S7ConnectionError(f"GetVarSubStreamed failed: return_value=0x{return_value:X}")
        if offset < len(payload) and payload[offset : offset + 1] == b"\x00":
            # Optional zero marker before some scalar/BLOB replies.
            if offset + 2 >= len(payload) or payload[offset + 1] not in (
                DataType.BLOB,
                DataType.WSTRING,
                DataType.S7STRING,
                DataType.TIMESPAN,
                DataType.LREAL,
                DataType.REAL,
                DataType.UDINT,
                DataType.ULINT,
                DataType.DINT,
                DataType.LINT,
                DataType.USINT,
                DataType.UINT,
                DataType.STRUCT,
            ):
                offset += 1
        if offset + 2 > len(payload):
            raise ValueError("missing PValue header")
        flags = payload[offset]
        datatype = payload[offset + 1]
        raw, _ = decode_pvalue_to_bytes(payload, offset)
        return _DecodedPValue(flags=flags, datatype=datatype, raw=raw)
    except S7ConnectionError:
        raise
    except (IndexError, ValueError) as exc:
        raise S7ConnectionError(f"Malformed GetVarSubStreamed response: {exc}") from exc


def _gvs_request(connection: _MetadataConnection, object_id: int, address: int) -> tuple[bytes, int]:
    old = uses_old_firmware_gvs_framing(connection)
    oq_version = int(getattr(connection.object_qualifier_version, "value", connection.object_qualifier_version))
    payload = build_get_var_substreamed_payload(
        object_id,
        address,
        old_firmware_framing=old,
        protocol_version=oq_version,
    )
    return payload, 0 if old else 4


def get_var_substreamed(connection: _MetadataConnection, object_id: int, address: int) -> _DecodedPValue:
    """Read one object attribute through GetVarSubStreamed."""
    payload, integrity_tail = _gvs_request(connection, object_id, address)
    response = connection.send_request(FunctionCode.GET_VAR_SUBSTREAMED, payload, integrity_tail=integrity_tail)
    return parse_get_var_substreamed_pvalue(response)


async def get_var_substreamed_async(connection: Any, object_id: int, address: int) -> _DecodedPValue:
    """Async counterpart of :func:`get_var_substreamed`."""
    payload, integrity_tail = _gvs_request(connection, object_id, address)
    response = await connection.send_request(FunctionCode.GET_VAR_SUBSTREAMED, payload, integrity_tail=integrity_tail)
    return parse_get_var_substreamed_pvalue(response)


def _ascii_field(data: bytes, start: int, length: int) -> str:
    return data[start : start + length].decode("ascii", errors="replace").rstrip("\x00 ")


def parse_cpu_identification_blob(data: bytes) -> tuple[str, str, tuple[int, int, int, int]]:
    """Parse the CPUProxy identification BLOB (AID 3753)."""
    if len(data) < 51:
        raise S7ProtocolError(f"CPU identification BLOB too short ({len(data)} bytes)")
    mlfb = _ascii_field(data, 8, 19)
    serial = _ascii_field(data, 28, 16)
    firmware = (data[47], data[48], data[49], data[50])
    return mlfb, serial, firmware


def _as_number(value: _DecodedPValue) -> float:
    raw = value.raw
    if value.datatype == DataType.LREAL and len(raw) >= 8:
        return struct.unpack(">d", raw[:8])[0]
    if value.datatype == DataType.REAL and len(raw) >= 4:
        return struct.unpack(">f", raw[:4])[0]
    if len(raw) == 8:
        return float(struct.unpack(">q", raw)[0])
    if len(raw) == 4:
        return float(struct.unpack(">i", raw)[0])
    if len(raw) == 2:
        return float(struct.unpack(">h", raw)[0])
    if len(raw) == 1:
        return float(raw[0])
    raise S7ProtocolError(f"unsupported numeric PValue datatype=0x{value.datatype:02X}")


def _as_milliseconds(value: _DecodedPValue) -> float:
    number = _as_number(value)
    if value.datatype in (DataType.REAL, DataType.LREAL):
        return number
    return number / 1000.0


def _as_wstring(value: _DecodedPValue) -> str:
    if value.datatype not in (DataType.WSTRING, DataType.S7STRING):
        raise S7ProtocolError(f"expected WString, got datatype=0x{value.datatype:02X}")
    text, _ = decode_wstring(value.raw, 0, len(value.raw))
    return text


def _parse_wstring_array(payload: bytes) -> list[str]:
    """Decode a WString array PValue from a GetVarSubStreamed reply."""
    return_value, offset = decode_uint64_vlq(payload, 0)
    if return_value != 0:
        raise S7ConnectionError(f"GetVarSubStreamed failed: return_value=0x{return_value:X}")
    if offset < len(payload) and payload[offset : offset + 1] == b"\x00":
        if offset + 2 >= len(payload) or payload[offset + 1] != DataType.WSTRING:
            offset += 1
    if offset + 2 > len(payload):
        raise S7ProtocolError("missing WString array header")
    flags = payload[offset]
    datatype = payload[offset + 1]
    offset += 2
    if datatype != DataType.WSTRING or not (flags & 0x10):
        raise S7ProtocolError(f"expected WString array, got flags=0x{flags:02X} datatype=0x{datatype:02X}")
    count, consumed = decode_uint32_vlq(payload, offset)
    offset += consumed
    names: list[str] = []
    for _ in range(count):
        length, consumed = decode_uint32_vlq(payload, offset)
        offset += consumed
        text, consumed = decode_wstring(payload, offset, length)
        offset += consumed
        names.append(text)
    return names


def read_cpu_info(connection: _MetadataConnection) -> CpuInfo:
    """Read PLC identity; skip ASRoot/ReleaseMngmt on plaintext FW2.x sessions."""
    ident = get_var_substreamed(connection, Ids.NATIVE_THE_CPU_PROXY_RID, Ids.CPU_PROXY_IDENTIFICATION)
    if ident.datatype != DataType.BLOB:
        raise S7ProtocolError(f"CPU identification is not a BLOB (datatype=0x{ident.datatype:02X})")
    mlfb, serial, firmware = parse_cpu_identification_blob(ident.raw)

    plc_name: Optional[str] = None
    try:
        name_value = get_var_substreamed(connection, Ids.NATIVE_THE_CPU_COMMON_RID, Ids.CPU_COMMON_PLC_NAME)
        plc_name = _as_wstring(name_value)
    except (S7ConnectionError, S7ProtocolError):
        if not uses_old_firmware_gvs_framing(connection):
            raise

    version_tia: Optional[tuple[int, int, int, int]] = None
    version2: Optional[tuple[int, int, int, int]] = None
    project_name: Optional[str] = None
    if not uses_old_firmware_gvs_framing(connection):
        versions = get_var_substreamed(connection, Ids.NATIVE_THE_AS_ROOT_RID, Ids.AS_ROOT_VERSIONS)
        if not (versions.flags & 0x10) or versions.datatype != DataType.USINT or len(versions.raw) < 8:
            raise S7ProtocolError("ASRoot versions reply is not an 8-byte USINT array")
        version_tia = (versions.raw[0], versions.raw[1], versions.raw[2], versions.raw[3])
        version2 = (versions.raw[4], versions.raw[5], versions.raw[6], versions.raw[7])
        old = uses_old_firmware_gvs_framing(connection)
        oq_version = int(getattr(connection.object_qualifier_version, "value", connection.object_qualifier_version))
        payload = build_get_var_substreamed_payload(
            Ids.RELEASE_MANAGEMENT_ROOT_RID,
            Ids.RELEASE_MANAGEMENT_VERSIONS_AND_NAME,
            old_firmware_framing=old,
            protocol_version=oq_version,
        )
        response = connection.send_request(
            FunctionCode.GET_VAR_SUBSTREAMED, payload, integrity_tail=0 if old else 4
        )
        try:
            names = _parse_wstring_array(response)
            if len(names) > 2:
                project_name = names[2]
        except (S7ConnectionError, S7ProtocolError):
            project_name = None

    return CpuInfo(
        mlfb=mlfb,
        serial=serial,
        firmware=firmware,
        plc_name=plc_name,
        project_name=project_name,
        version_tia=version_tia,
        version2=version2,
    )


def read_cpu_cycle_time(connection: _MetadataConnection) -> CpuCycleTime:
    """Read scan-cycle statistics from theCPUexecUnit."""

    def optional(address: int) -> Optional[float]:
        try:
            return _as_milliseconds(get_var_substreamed(connection, Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, address))
        except (S7ConnectionError, S7ProtocolError):
            return None

    shortest = _as_milliseconds(
        get_var_substreamed(connection, Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, Ids.CPU_EXEC_UNIT_SHORTEST_SCAN_CYCLE)
    )
    current = _as_milliseconds(
        get_var_substreamed(connection, Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, Ids.CPU_EXEC_UNIT_CURRENT_SCAN_CYCLE)
    )
    longest = _as_milliseconds(
        get_var_substreamed(connection, Ids.NATIVE_THE_CPU_EXEC_UNIT_RID, Ids.CPU_EXEC_UNIT_LONGEST_SCAN_CYCLE)
    )
    return CpuCycleTime(
        shortest_ms=shortest,
        current_ms=current,
        longest_ms=longest,
        configured_minimum_ms=optional(Ids.CPU_EXEC_UNIT_CONFIGURED_MIN_SCAN_CYCLE),
        configured_maximum_ms=optional(Ids.CPU_EXEC_UNIT_CONFIGURED_MAX_SCAN_CYCLE),
    )


_MEMORY_AREAS = (
    ("load", "Load memory", Ids.CPU_COMMON_LOAD_MEMORY_TOTAL, Ids.CPU_COMMON_LOAD_MEMORY_USED),
    ("work", "Work memory", Ids.CPU_COMMON_WORK_MEMORY_TOTAL, Ids.CPU_COMMON_WORK_MEMORY_USED),
    ("work-code", "Work memory code", Ids.CPU_COMMON_WORK_MEMORY_CODE_TOTAL, Ids.CPU_COMMON_WORK_MEMORY_CODE_USED),
    ("work-data", "Work memory data", Ids.CPU_COMMON_WORK_MEMORY_DATA_TOTAL, Ids.CPU_COMMON_WORK_MEMORY_DATA_USED),
    ("retain", "Retain memory", Ids.CPU_COMMON_RETAIN_MEMORY_TOTAL, Ids.CPU_COMMON_RETAIN_MEMORY_USED),
)


def read_cpu_memory_usage(connection: _MetadataConnection) -> CpuMemoryUsage:
    """Read available CPU memory areas from CPUCommon."""
    areas: list[CpuMemoryArea] = []
    for key, name, total_aid, used_aid in _MEMORY_AREAS:
        try:
            total = int(_as_number(get_var_substreamed(connection, Ids.NATIVE_THE_CPU_COMMON_RID, total_aid)))
            used = int(_as_number(get_var_substreamed(connection, Ids.NATIVE_THE_CPU_COMMON_RID, used_aid)))
        except (S7ConnectionError, S7ProtocolError):
            continue
        if total <= 0:
            continue
        areas.append(CpuMemoryArea(key=key, name=name, total_bytes=total, used_bytes=max(0, used)))
    if not areas:
        raise S7ProtocolError("PLC reported no readable CPU memory areas")
    return CpuMemoryUsage(areas=tuple(areas))


def parse_text_container_lcids(response: bytes) -> CpuCultureInfo:
    """Parse text-container LCIDs from an EXPLORE(theTextContainer) response."""
    from .typeinfo import START_OF_OBJECT, parse_object_list
    from .vlq import decode_uint32_vlq as _decode_u32

    try:
        return_value, offset = _decode_u32(response, 0)
    except (ValueError, IndexError) as exc:
        raise S7ProtocolError(f"Malformed text-container EXPLORE: {exc}") from exc
    if return_value != 0:
        raise S7ProtocolError(f"Text-container EXPLORE failed: return_value=0x{return_value:X}")

    language_ids: list[int] = []
    for _ in range(8):
        offset = response.find(bytes([START_OF_OBJECT]), offset)
        if offset < 0:
            break
        try:
            objects, _ = parse_object_list(response, offset)
        except (ValueError, IndexError, struct.error, RecursionError):
            objects = []
        pending = list(objects)
        while pending:
            obj = pending.pop()
            raw = obj.attributes.get(Ids.TEXT_CONTAINER_LCIDS)
            if raw is not None:
                if len(raw) >= 2 and len(raw) % 2 == 0:
                    language_ids = list(struct.unpack(f">{len(raw) // 2}H", raw))
                elif len(raw) >= 4 and len(raw) % 4 == 0:
                    language_ids = list(struct.unpack(f">{len(raw) // 4}I", raw))
                elif len(raw) == 2:
                    language_ids = [struct.unpack(">H", raw)[0]]
                elif len(raw) == 4:
                    language_ids = [struct.unpack(">I", raw)[0]]
                return CpuCultureInfo(language_ids=tuple(dict.fromkeys(language_ids)))
            pending.extend(obj.objects)
            if obj.relation_id == Ids.NATIVE_THE_TEXT_CONTAINER_RID or obj.class_id == Ids.TEXT_CONTAINER_CLASS_RID:
                # Keep searching children/siblings for the LCID attribute.
                pass
        offset += 1
    return CpuCultureInfo(language_ids=())


def build_text_container_explore_payload() -> bytes:
    """EXPLORE payload for theTextContainer asking only for LCIDs."""
    payload = bytearray()
    payload += struct.pack(">I", Ids.NATIVE_THE_TEXT_CONTAINER_RID)
    payload += encode_uint32_vlq(0)  # ExploreRequestId
    payload += bytes([0])  # ExploreChildsRecursive
    payload += bytes([1])  # mid flag
    payload += bytes([1])  # ExploreParents (match S7CommPlusDriver)
    payload += bytes([0])  # no filter objects
    payload += encode_uint32_vlq(1)
    payload += encode_uint32_vlq(Ids.TEXT_CONTAINER_LCIDS)
    payload += struct.pack(">I", 0) + bytes([0])
    return bytes(payload)


def read_cpu_culture_info(connection: _MetadataConnection) -> CpuCultureInfo:
    """Read text-container LCIDs via EXPLORE.

    Older firmware without a text container (e.g. S7-1200 FW2.2) answers
    ``OBJECT_NOT_FOUND``; that is treated as an empty language catalog.
    """
    from .codec import parse_or_raise_for_return_value
    from .error import S7ReturnValueError

    payload = build_text_container_explore_payload()
    response = connection.send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
    try:
        parse_or_raise_for_return_value(response, "CPU culture info")
    except S7ReturnValueError:
        return CpuCultureInfo(language_ids=())
    return parse_text_container_lcids(response)
