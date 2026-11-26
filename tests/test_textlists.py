"""Unit tests for online text-list decoding and resolution."""

from __future__ import annotations

import struct

from s7commplus.protocol import DataType, Ids
from s7commplus.textlists import (
    TextList,
    TextListCatalog,
    TextListEntry,
    TextListScope,
    TextListType,
    build_text_list_explore_payload,
    decode_text_list_library,
    parse_text_library_explore,
)
from s7commplus.vlq import encode_uint32_vlq


def _write_text(buf: bytearray, offset: int, text: str) -> None:
    raw = text.encode("utf-8")
    struct.pack_into("<H", buf, offset, len(raw))
    buf[offset + 2 : offset + 2 + len(raw)] = raw


def test_decode_32bit_text_list_entries() -> None:
    list_table = bytearray(26)
    struct.pack_into("<I", list_table, 16, 1)
    struct.pack_into("<H", list_table, 20, 0x1234)
    struct.pack_into("<I", list_table, 22, 16)

    entry_table = bytearray(36)
    struct.pack_into("<I", entry_table, 16, 2)
    struct.pack_into("<I", entry_table, 20, 70_000)
    struct.pack_into("<I", entry_table, 24, 8)
    struct.pack_into("<I", entry_table, 28, 0xFFFFFFFF)
    struct.pack_into("<I", entry_table, 32, 15)

    string_table = bytearray(21)
    _write_text(string_table, 8, "Alpha")
    _write_text(string_table, 15, "Last")

    lists = decode_text_list_library(
        bytes(list_table), bytes(entry_table), bytes(string_table), 1031, TextListScope.LANGUAGE_SPECIFIC
    )
    assert len(lists) == 1
    assert lists[0].list_id == 0x1234
    assert lists[0].entries[0].from_value == 70_000
    assert lists[0].entries[0].text == "Alpha"
    assert lists[0].entries[1].from_value == -1
    assert lists[0].entries[1].text == "Last"


def test_decode_legacy_16bit_text_list_entries() -> None:
    list_table = bytearray(26)
    struct.pack_into("<I", list_table, 16, 1)
    struct.pack_into("<H", list_table, 20, 0x0042)
    struct.pack_into("<I", list_table, 22, 16)

    entry_table = bytearray(32)
    struct.pack_into("<I", entry_table, 16, 2)
    struct.pack_into("<H", entry_table, 20, 1)
    struct.pack_into("<I", entry_table, 22, 8)
    struct.pack_into("<H", entry_table, 26, 0xFFFF)
    struct.pack_into("<I", entry_table, 28, 15)

    string_table = bytearray(21)
    _write_text(string_table, 8, "Alpha")
    _write_text(string_table, 15, "Last")

    lists = decode_text_list_library(
        bytes(list_table), bytes(entry_table), bytes(string_table), 1031, TextListScope.LANGUAGE_SPECIFIC
    )
    assert lists[0].list_id == 0x0042
    assert [e.from_value for e in lists[0].entries] == [1, 0xFFFF]


def test_text_list_resolution_prefers_exact_over_range() -> None:
    entries = (
        TextListEntry(10, 20, "Range"),
        TextListEntry(15, 15, "Exact"),
        TextListEntry(1, 1, "First"),
    )
    text_list = TextList(1, 1031, TextListScope.LANGUAGE_SPECIFIC, TextListType.UNKNOWN, entries)
    assert text_list.try_resolve(15) == "Exact"
    assert text_list.try_resolve(16) == "Range"


def test_catalog_resolves_name_with_legacy_suffix_and_language_fallback() -> None:
    independent = TextList(
        41,
        0,
        TextListScope.LANGUAGE_INDEPENDENT,
        TextListType.SYSTEM,
        (TextListEntry(7, 7, "Ind"),),
    )
    specific = TextList(
        42,
        1031,
        TextListScope.LANGUAGE_SPECIFIC,
        TextListType.USER,
        (TextListEntry(1, 1, "De"),),
    )
    catalog = TextListCatalog((1031,), (independent, specific))
    assert catalog.resolve_text("42", 1, 1031) == "De"
    assert catalog.resolve_text("42W", 1, 1031) == "De"
    assert catalog.resolve_text("42W", 7, 1031) == "Ind"  # falls back via list_id-1 then lang 0
    assert catalog.try_resolve(41, 7, 1031) == "Ind"


def test_build_text_list_explore_payload_targets_base_relation() -> None:
    payload = build_text_list_explore_payload(Ids.TEXT_LIST_LIBRARY_BASE_RELATION_ID)
    assert payload.startswith(struct.pack(">I", Ids.TEXT_LIST_LIBRARY_BASE_RELATION_ID))
    assert payload[4:5] == b"\x00"  # ExploreRequestId VLQ 0 starts here


def test_parse_text_library_explore_roundtrip() -> None:
    from s7commplus.codec import decode_pvalue_to_bytes

    # Build a minimal TextLibrary object: OffsetArea BlobArray[2], StringArea Blob.
    list_blob = bytearray(26)
    struct.pack_into("<I", list_blob, 16, 1)
    struct.pack_into("<H", list_blob, 20, 9)
    struct.pack_into("<I", list_blob, 22, 16)
    entry_blob = bytearray(28)
    struct.pack_into("<I", entry_blob, 16, 1)
    struct.pack_into("<I", entry_blob, 20, 3)
    struct.pack_into("<I", entry_blob, 24, 8)
    string_blob = bytearray(16)
    _write_text(string_blob, 8, "Hi")

    def encode_blob(payload: bytes) -> bytes:
        return bytes([0x00, DataType.BLOB]) + encode_uint32_vlq(0) + encode_uint32_vlq(len(payload)) + payload

    offset_array = bytes([0x10, DataType.BLOB]) + encode_uint32_vlq(2)
    # Array elements: root_id + length + data (no nested flags)
    for blob in (bytes(list_blob), bytes(entry_blob)):
        offset_array += encode_uint32_vlq(0) + encode_uint32_vlq(len(blob)) + blob

    attr_offset = bytes([0xA3]) + encode_uint32_vlq(Ids.TEXT_LIBRARY_OFFSET_AREA) + offset_array
    attr_string = bytes([0xA3]) + encode_uint32_vlq(Ids.TEXT_LIBRARY_STRING_AREA) + encode_blob(bytes(string_blob))
    obj = (
        bytes([0xA1])
        + struct.pack(">I", Ids.TEXT_LIST_LIBRARY_BASE_RELATION_ID)
        + encode_uint32_vlq(Ids.TEXT_LIBRARY_CLASS_RID)
        + encode_uint32_vlq(0)
        + encode_uint32_vlq(0)
        + attr_offset
        + attr_string
        + bytes([0xA2])
    )
    response = encode_uint32_vlq(0) + obj
    parsed = parse_text_library_explore(response)
    assert parsed is not None
    offsets, strings = parsed
    assert len(offsets) == 2
    lists = decode_text_list_library(offsets[0], offsets[1], strings, 0, TextListScope.LANGUAGE_INDEPENDENT)
    assert lists[0].list_id == 9
    assert lists[0].entries[0].text == "Hi"

    # BlobArray decode_pvalue_to_bytes stays aligned for object walking.
    raw, consumed = decode_pvalue_to_bytes(offset_array, 0)
    assert consumed == len(offset_array)
    assert len(raw) == 4 + len(list_blob) + 4 + len(entry_blob)
