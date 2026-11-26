"""Unit tests for alarm-class engineering metadata (AID 7853)."""

from __future__ import annotations

import struct

from s7commplus.alarm_classes import (
    build_alarm_classes_explore_payload,
    parse_alarm_class_list_xml,
    parse_alarm_classes_from_explore,
)
from s7commplus.protocol import DataType, ElementID, Ids
from s7commplus.vlq import encode_uint32_vlq, encode_uint64_vlq


def test_parse_alarm_class_list_xml() -> None:
    xml = (
        "<AlarmClassList>"
        "<AlarmClass Name='PlcError' Id='37' Ack='false' Prio='10'>"
        "<DisplayName LCID='1031'>Fehler</DisplayName>"
        "</AlarmClass>"
        "</AlarmClassList>"
    )
    classes = parse_alarm_class_list_xml(xml)
    assert len(classes) == 1
    assert classes[0].id == 37
    assert classes[0].name == "PlcError"
    assert classes[0].priority == 10
    assert classes[0].acknowledgement_required is False
    assert classes[0].display_name(1031) == "Fehler"


def test_build_alarm_classes_explore_payload() -> None:
    payload = build_alarm_classes_explore_payload()
    assert payload.startswith(struct.pack(">I", Ids.NATIVE_THE_PLC_PROGRAM_RID))
    assert encode_uint32_vlq(Ids.BLOCK_ALARM_DESCRIPTION) in payload


def test_parse_alarm_classes_from_explore_sparse_blob() -> None:
    xml = b"<AlarmClassList><AlarmClass Name='PlcError' Id='37' Ack='false' Prio='10'/></AlarmClassList>"
    sparse = encode_uint32_vlq(1) + encode_uint32_vlq(0) + encode_uint32_vlq(len(xml)) + xml + encode_uint32_vlq(0)
    attr = (
        bytes([ElementID.ATTRIBUTE])
        + encode_uint32_vlq(Ids.BLOCK_ALARM_DESCRIPTION)
        + bytes([0x40, DataType.BLOB])
        + sparse
    )
    obj = (
        bytes([ElementID.START_OF_OBJECT])
        + struct.pack(">I", 123)
        + encode_uint32_vlq(Ids.FB_CLASS_RID)
        + encode_uint32_vlq(0)
        + encode_uint32_vlq(0)
        + attr
        + bytes([ElementID.TERMINATING_OBJECT])
    )
    response = encode_uint64_vlq(0) + struct.pack(">I", Ids.NATIVE_THE_PLC_PROGRAM_RID) + encode_uint32_vlq(1) + obj
    classes = parse_alarm_classes_from_explore(response)
    assert len(classes) == 1
    assert classes[0].name == "PlcError"
    assert classes[0].id == 37
