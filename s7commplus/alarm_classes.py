"""Alarm class catalog from block engineering metadata (AID 7853).

Matches S7CommPlusDriver ``GetAlarmClasses``: EXPLORE thePLCProgram for
``Block_AlarmDescription`` sparse blobs and parse embedded ``AlarmClassList`` XML.
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional, Protocol

from .codec import parse_or_raise_for_return_value
from .error import S7ProtocolError
from .protocol import DataType, ElementID, FunctionCode, Ids
from .vlq import decode_uint32_vlq, encode_uint32_vlq


@dataclass(frozen=True)
class AlarmClass:
    """One configured alarm class from the downloaded program."""

    id: int
    name: str
    priority: Optional[int] = None
    acknowledgement_required: Optional[bool] = None
    display_names: tuple[tuple[int, str], ...] = ()
    short_names: tuple[tuple[int, str], ...] = ()

    def display_name(self, language_id: int) -> Optional[str]:
        for lcid, text in self.display_names:
            if lcid == language_id:
                return text
        return None

    def short_name(self, language_id: int) -> Optional[str]:
        for lcid, text in self.short_names:
            if lcid == language_id:
                return text
        return None


class _AlarmClassConnection(Protocol):
    def send_request(
        self, function_code: int, payload: bytes = b"", integrity_tail: int = 4, reassemble: bool = False
    ) -> bytes: ...


def build_alarm_classes_explore_payload(*, with_integrity: bool = True) -> bytes:
    """EXPLORE thePLCProgram asking only for Block_AlarmDescription."""
    from .client import _build_explore_request

    return _build_explore_request(
        Ids.NATIVE_THE_PLC_PROGRAM_RID,
        [Ids.BLOCK_ALARM_DESCRIPTION],
        with_integrity=with_integrity,
    )


def parse_alarm_class_list_xml(xml_data: bytes | str) -> list[AlarmClass]:
    """Parse one ``AlarmClassList`` document into class definitions."""
    if isinstance(xml_data, bytes):
        root = ET.fromstring(xml_data)
    else:
        root = ET.fromstring(xml_data)
    if root.tag != "AlarmClassList":
        raise S7ProtocolError(f"Expected AlarmClassList root, got {root.tag!r}")

    by_id: dict[int, AlarmClass] = {}
    for element in root.findall("AlarmClass"):
        raw_id = element.get("Id")
        name = element.get("Name")
        if raw_id is None or name is None or not str(name).strip():
            raise S7ProtocolError("Invalid alarm class definition")
        class_id = int(raw_id)
        if class_id < 0 or class_id > 0xFFFF:
            raise S7ProtocolError(f"Alarm class id out of range: {class_id}")
        priority = _optional_int(element.get("Prio"))
        if priority is not None and priority < 0:
            raise S7ProtocolError(f"Invalid alarm class priority: {priority}")
        ack = _optional_bool(element.get("Ack"))
        display_names = _read_texts(element, "DisplayName")
        short_names = _read_texts(element, "ShortName")
        previous = by_id.get(class_id)
        if previous is not None:
            if previous.name != name:
                raise S7ProtocolError(f"Conflicting alarm class name for id {class_id}")
            if (
                previous.priority is not None
                and priority is not None
                and previous.priority != priority
            ):
                raise S7ProtocolError(f"Conflicting alarm class priority for id {class_id}")
            if (
                previous.acknowledgement_required is not None
                and ack is not None
                and previous.acknowledgement_required != ack
            ):
                raise S7ProtocolError(f"Conflicting alarm class Ack for id {class_id}")
            priority = priority if priority is not None else previous.priority
            ack = ack if ack is not None else previous.acknowledgement_required
            display_names = _merge_texts(previous.display_names, display_names)
            short_names = _merge_texts(previous.short_names, short_names)
        by_id[class_id] = AlarmClass(
            id=class_id,
            name=str(name),
            priority=priority,
            acknowledgement_required=ack,
            display_names=tuple(sorted(display_names)),
            short_names=tuple(sorted(short_names)),
        )
    return [by_id[key] for key in sorted(by_id)]


def parse_alarm_classes_from_explore(response: bytes) -> list[AlarmClass]:
    """Collect alarm classes from an EXPLORE(thePLCProgram, AlarmDescription) reply."""
    offset = parse_or_raise_for_return_value(response, "Alarm classes")
    by_id: dict[int, AlarmClass] = {}
    while True:
        found = response.find(bytes([ElementID.ATTRIBUTE]), offset)
        if found < 0:
            break
        try:
            attr_id, consumed = decode_uint32_vlq(response, found + 1)
        except (ValueError, IndexError):
            offset = found + 1
            continue
        pos = found + 1 + consumed
        if attr_id != Ids.BLOCK_ALARM_DESCRIPTION or pos + 2 > len(response):
            offset = found + 1
            continue
        flags = response[pos]
        datatype = response[pos + 1]
        pos += 2
        if datatype != DataType.BLOB or flags != 0x40:
            offset = found + 1
            continue
        try:
            blobs, _ = _decode_blob_sparse_array(response, pos)
        except (ValueError, IndexError, struct.error):
            offset = found + 1
            continue
        xml_blob = blobs.get(1)
        if xml_blob is None:
            offset = found + 1
            continue
        for alarm_class in parse_alarm_class_list_xml(xml_blob):
            previous = by_id.get(alarm_class.id)
            if previous is None:
                by_id[alarm_class.id] = alarm_class
                continue
            # Merge translations across blocks; conflicts raise in parse_alarm_class_list_xml
            # when the same document repeats — here only merge compatible entries.
            if previous.name != alarm_class.name:
                raise S7ProtocolError(f"Conflicting alarm class name for id {alarm_class.id}")
            by_id[alarm_class.id] = AlarmClass(
                id=alarm_class.id,
                name=alarm_class.name,
                priority=alarm_class.priority if alarm_class.priority is not None else previous.priority,
                acknowledgement_required=(
                    alarm_class.acknowledgement_required
                    if alarm_class.acknowledgement_required is not None
                    else previous.acknowledgement_required
                ),
                display_names=_merge_texts(previous.display_names, alarm_class.display_names),
                short_names=_merge_texts(previous.short_names, alarm_class.short_names),
            )
        offset = found + 1
    return [by_id[key] for key in sorted(by_id)]


def read_alarm_classes(connection: _AlarmClassConnection) -> list[AlarmClass]:
    """EXPLORE program blocks for alarm-class engineering metadata."""
    from .metadata import explore_integrity_framing

    with_integrity, integrity_tail = explore_integrity_framing(connection)  # type: ignore[arg-type]
    payload = build_alarm_classes_explore_payload(with_integrity=with_integrity)
    response = connection.send_request(
        FunctionCode.EXPLORE, payload, integrity_tail=integrity_tail, reassemble=True
    )
    return parse_alarm_classes_from_explore(response)


def _decode_blob_sparse_array(data: bytes, offset: int) -> tuple[dict[int, bytes], int]:
    """Decode a sparse Blob array starting after the flags/datatype bytes."""
    blobs: dict[int, bytes] = {}
    while offset < len(data):
        key, consumed = decode_uint32_vlq(data, offset)
        offset += consumed
        if key == 0:
            break
        _root, consumed = decode_uint32_vlq(data, offset)
        offset += consumed
        length, consumed = decode_uint32_vlq(data, offset)
        offset += consumed
        if offset + length > len(data):
            raise ValueError("Truncated sparse blob")
        blobs[key] = data[offset : offset + length]
        offset += length
    return blobs, offset


def _read_texts(element: ET.Element, tag: str) -> list[tuple[int, str]]:
    texts: list[tuple[int, str]] = []
    for child in element.findall(tag):
        lcid_raw = child.get("LCID")
        if lcid_raw is None:
            raise S7ProtocolError(f"Missing LCID on {tag}")
        lcid = int(lcid_raw)
        if lcid < 0 or lcid > 0xFFFF:
            raise S7ProtocolError(f"Invalid LCID on {tag}: {lcid}")
        texts.append((lcid, child.text or ""))
    return texts


def _merge_texts(
    left: tuple[tuple[int, str], ...] | list[tuple[int, str]],
    right: tuple[tuple[int, str], ...] | list[tuple[int, str]],
) -> tuple[tuple[int, str], ...]:
    merged: dict[int, str] = dict(left)
    for lcid, text in right:
        previous = merged.get(lcid)
        if previous is not None and previous != text:
            raise S7ProtocolError(f"Conflicting alarm class translation for LCID {lcid}")
        merged[lcid] = text
    return tuple(sorted(merged.items()))


def _optional_int(value: str | None) -> Optional[int]:
    if value is None:
        return None
    return int(value)


def _optional_bool(value: str | None) -> Optional[bool]:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in ("true", "1"):
        return True
    if lowered in ("false", "0"):
        return False
    raise S7ProtocolError(f"Invalid boolean attribute: {value!r}")
