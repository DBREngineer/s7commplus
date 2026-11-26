"""Unit tests for CPU metadata helpers (GetVarSubStreamed framing + parsers)."""

from __future__ import annotations

import struct

from s7commplus.metadata import (
    build_get_var_substreamed_payload,
    parse_cpu_identification_blob,
    parse_get_var_substreamed_pvalue,
    parse_text_container_lcids,
    uses_old_firmware_gvs_framing,
)
from s7commplus.protocol import DataType, Ids, ProtocolVersion
from s7commplus.vlq import encode_uint32_vlq, encode_uint64_vlq


class _Conn:
    def __init__(self, protocol_version: int, secured_session: bool) -> None:
        self.protocol_version = protocol_version
        self.secured_session = secured_session
        self.object_qualifier_version = protocol_version


def test_old_firmware_framing_only_on_plaintext_v1() -> None:
    assert uses_old_firmware_gvs_framing(_Conn(ProtocolVersion.V1, False))
    assert not uses_old_firmware_gvs_framing(_Conn(ProtocolVersion.V1, True))
    assert not uses_old_firmware_gvs_framing(_Conn(ProtocolVersion.V2, False))


def test_old_firmware_payload_has_fixed_key_qualifier_and_integrity() -> None:
    payload = build_get_var_substreamed_payload(49, 3753, old_firmware_framing=True)
    assert payload.startswith(struct.pack(">I", 49))
    assert bytes([0x20, DataType.UDINT, 0x01]) in payload
    # Ends with fixed UInt32 integrity id 0 (no VLQ fill trailer).
    assert payload.endswith(struct.pack(">I", 0))
    # No 0x00 attribute-list terminator after KeyQualifier on this path:
    # KeyQualifier value is the fixed UDInt 1 immediately before integrity.
    assert struct.pack(">I", 1) + struct.pack(">I", 0) == payload[-8:]


def test_parse_identification_blob() -> None:
    data = bytearray(51)
    data[8:27] = b"6ES7 212-1BD30-0XB0 "
    data[28:44] = b"SZVX7YU6001633  "
    data[47:51] = bytes([2, 2, 0, 0])
    mlfb, serial, firmware = parse_cpu_identification_blob(bytes(data))
    assert mlfb == "6ES7 212-1BD30-0XB0"
    assert serial == "SZVX7YU6001633"
    assert firmware == (2, 2, 0, 0)


def test_parse_gvs_blob_response() -> None:
    blob = b"\x00" * 8 + b"6ES7 212-1BD30-0XB0 " + b"SZVX7YU6001633  " + b"\x00\x00\x00" + bytes([2, 2, 0, 0])
    body = encode_uint64_vlq(0)
    body += bytes([0x00, DataType.BLOB]) + encode_uint32_vlq(0) + encode_uint32_vlq(len(blob)) + blob
    decoded = parse_get_var_substreamed_pvalue(body)
    assert decoded.datatype == DataType.BLOB
    mlfb, _, fw = parse_cpu_identification_blob(decoded.raw)
    assert mlfb.startswith("6ES7")
    assert fw == (2, 2, 0, 0)


def test_parse_text_container_lcids_uint_array() -> None:
    # Minimal EXPLORE: ReturnValue 0 + one object with LCID attribute as UINT array raw.
    from s7commplus.vlq import encode_uint32_vlq as ev

    attr = bytes([0xA3]) + ev(Ids.TEXT_CONTAINER_LCIDS) + bytes([0x10, DataType.UINT]) + ev(2) + struct.pack(">HH", 1031, 1033)
    obj = bytes([0xA1]) + struct.pack(">I", Ids.NATIVE_THE_TEXT_CONTAINER_RID) + ev(Ids.TEXT_CONTAINER_CLASS_RID) + ev(0) + ev(0)
    obj += attr + bytes([0xA2])
    response = encode_uint32_vlq(0) + obj
    culture = parse_text_container_lcids(response)
    assert culture.language_ids == (1031, 1033)
    assert culture.primary_language_id == 1031
