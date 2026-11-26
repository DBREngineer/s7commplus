"""Online text-list libraries ported from S7CommPlusDriver.

Reads language-independent and language-specific text libraries via EXPLORE
of relation ``0x8A370000`` (+ LCID), then decodes the three binary tables
carried by the TextLibrary object (offset blobs + string area).
"""

from __future__ import annotations

import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, Optional, Protocol

from .codec import parse_or_raise_for_return_value
from .error import S7ProtocolError, S7ReturnValueError
from .protocol import FunctionCode, Ids
from .typeinfo import START_OF_OBJECT, parse_object_list
from .vlq import decode_uint32_vlq, encode_uint32_vlq


class TextListScope(Enum):
    """Whether a decoded list came from the shared or a language library."""

    LANGUAGE_INDEPENDENT = "language_independent"
    LANGUAGE_SPECIFIC = "language_specific"


class TextListType(Enum):
    """Best-effort classification from the runtime list id range."""

    UNKNOWN = "unknown"
    USER = "user"
    SYSTEM = "system"


@dataclass(frozen=True)
class TextListEntry:
    """One value-or-range mapping to a UTF-8 text."""

    from_value: int
    to_value: int
    text: str

    @property
    def is_range(self) -> bool:
        return self.from_value != self.to_value


@dataclass(frozen=True)
class TextList:
    """One text list (runtime id) for one language."""

    list_id: int
    language_id: int
    scope: TextListScope
    text_list_type: TextListType
    entries: tuple[TextListEntry, ...]

    def try_resolve(self, value: int) -> Optional[str]:
        """Resolve ``value``: exact entries first, then ranges."""
        for entry in self.entries:
            if not entry.is_range and entry.from_value == value:
                return entry.text
        for entry in self.entries:
            if entry.is_range and entry.from_value <= value <= entry.to_value:
                return entry.text
        return None


@dataclass(frozen=True)
class TextListCatalog:
    """Resolved catalog of text lists for one or more LCIDs."""

    language_ids: tuple[int, ...]
    text_lists: tuple[TextList, ...]
    _index: Mapping[tuple[int, int], TextList] = field(default_factory=dict, init=False, repr=False, compare=False)

    EMPTY: ClassVar["TextListCatalog"]

    def __post_init__(self) -> None:
        index: dict[tuple[int, int], TextList] = {}
        for text_list in self.text_lists:
            key = (text_list.language_id, text_list.list_id)
            if key not in index:
                index[key] = text_list
        object.__setattr__(self, "_index", index)

    def resolve_text(self, text_list_name: str, value: int, language_id: int) -> Optional[str]:
        """Resolve a TIA placeholder name (digits, optional ``W``/``w`` suffix)."""
        list_id, has_legacy_suffix = _parse_text_list_id(text_list_name)
        if list_id is None:
            return None
        text = self.try_resolve(list_id, value, language_id)
        if text is not None:
            return text
        if has_legacy_suffix and list_id > 0:
            return self.try_resolve(list_id - 1, value, language_id)
        return None

    def try_resolve(self, list_id: int, value: int, language_id: int) -> Optional[str]:
        """Resolve by numeric list id, falling back to language-independent lists."""
        text = self._try_resolve_in_language(list_id, value, language_id)
        if text is not None:
            return text
        if language_id != 0:
            return self._try_resolve_in_language(list_id, value, 0)
        return None

    def _try_resolve_in_language(self, list_id: int, value: int, language_id: int) -> Optional[str]:
        text_list = self._index.get((language_id, list_id))
        if text_list is None:
            return None
        return text_list.try_resolve(value)


TextListCatalog.EMPTY = TextListCatalog((), ())  # type: ignore[misc]


class _TextListConnection(Protocol):
    def send_request(
        self, function_code: int, payload: bytes = b"", integrity_tail: int = 4, reassemble: bool = False
    ) -> bytes: ...


def classify_text_list(list_id: int) -> TextListType:
    """Best-effort user/system split matching S7CommPlusDriver."""
    if 512 <= list_id < 32768:
        return TextListType.USER
    return TextListType.SYSTEM


def decode_text_list_library(
    list_table: bytes,
    entry_table: bytes,
    string_table: bytes,
    language_id: int,
    scope: TextListScope,
) -> list[TextList]:
    """Decode the three binary tables of one TextLibrary object.

    Raises:
        S7ProtocolError: When the tables are truncated or inconsistent.
    """
    if len(list_table) < 20:
        raise S7ProtocolError("Text-list list table is too short")

    pos = 16
    list_count = _u32_le(list_table, pos)
    pos += 4
    decoded_texts: dict[int, str] = {}
    lists: list[TextList] = []

    for _ in range(list_count):
        if pos + 6 > len(list_table):
            raise S7ProtocolError("Text-list list table truncated")
        list_id = struct.unpack_from("<H", list_table, pos)[0]
        entry_offset = _u32_le(list_table, pos + 2)
        pos += 6
        entries = _read_entries(entry_table, string_table, entry_offset, decoded_texts)
        lists.append(
            TextList(
                list_id=list_id,
                language_id=language_id,
                scope=scope,
                text_list_type=classify_text_list(list_id),
                entries=tuple(entries),
            )
        )
    return lists


def build_text_list_explore_payload(relation_id: int) -> bytes:
    """EXPLORE payload for one text-list library relation (no attribute filter)."""
    payload = bytearray()
    payload += struct.pack(">I", relation_id & 0xFFFFFFFF)
    payload += encode_uint32_vlq(0)  # ExploreRequestId
    payload += bytes([0])  # ExploreChildsRecursive
    payload += bytes([1])  # mid / WithIntegrityId
    payload += bytes([0])  # ExploreParents
    payload += bytes([0])  # no filter objects
    payload += encode_uint32_vlq(0)  # empty AddressList → all attributes
    payload += struct.pack(">I", 0) + bytes([0])
    return bytes(payload)


def parse_text_library_explore(response: bytes) -> Optional[tuple[list[bytes], bytes]]:
    """Extract offset-area blobs and string-area blob from an EXPLORE reply.

    Returns ``None`` when the response has no TextLibrary object (empty library).
    """
    try:
        offset = parse_or_raise_for_return_value(response, "Text-list library")
    except S7ReturnValueError:
        return None

    for _ in range(8):
        found = response.find(bytes([START_OF_OBJECT]), offset)
        if found < 0:
            break
        try:
            objects, _ = parse_object_list(response, found)
        except (ValueError, IndexError, struct.error, RecursionError):
            objects = []
        pending = list(objects)
        while pending:
            obj = pending.pop()
            if obj.class_id == Ids.TEXT_LIBRARY_CLASS_RID:
                offset_raw = obj.attributes.get(Ids.TEXT_LIBRARY_OFFSET_AREA)
                string_raw = obj.attributes.get(Ids.TEXT_LIBRARY_STRING_AREA)
                if offset_raw is None or string_raw is None:
                    return None
                blobs = _unpack_length_prefixed_blobs(offset_raw)
                if len(blobs) < 2:
                    raise S7ProtocolError("TextLibraryOffsetArea needs at least two blobs")
                return blobs, string_raw
            pending.extend(obj.objects)
        offset = found + 1
    return None


def read_text_lists(
    connection: _TextListConnection,
    language_ids: Sequence[int] | None = None,
    *,
    culture_language_ids: Sequence[int] | None = None,
) -> TextListCatalog:
    """Read text lists for ``language_ids`` (or culture LCIDs when omitted).

    Always includes the language-independent library (language_id 0).
    Missing libraries or empty objects yield no lists for that language.
    """
    requested = list(dict.fromkeys(int(x) for x in (language_ids or ())))
    if not requested:
        requested = list(dict.fromkeys(int(x) for x in (culture_language_ids or ())))

    for language_id in requested:
        if language_id < 0 or language_id > 0xFFFF:
            raise ValueError(f"language_id out of range: {language_id}")

    lists: list[TextList] = []
    _append_library(connection, 0, Ids.TEXT_LIST_LIBRARY_BASE_RELATION_ID, TextListScope.LANGUAGE_INDEPENDENT, lists)
    for language_id in requested:
        if language_id == 0:
            continue
        relation = Ids.TEXT_LIST_LIBRARY_BASE_RELATION_ID + (language_id & 0xFFFF)
        _append_library(connection, language_id, relation, TextListScope.LANGUAGE_SPECIFIC, lists)
    return TextListCatalog(tuple(requested), tuple(lists))


def _append_library(
    connection: _TextListConnection,
    language_id: int,
    relation_id: int,
    scope: TextListScope,
    lists: list[TextList],
) -> None:
    payload = build_text_list_explore_payload(relation_id)
    response = connection.send_request(FunctionCode.EXPLORE, payload, integrity_tail=5, reassemble=True)
    parsed = parse_text_library_explore(response)
    if parsed is None:
        return
    offset_blobs, string_area = parsed
    lists.extend(
        decode_text_list_library(offset_blobs[0], offset_blobs[1], string_area, language_id, scope)
    )


def _unpack_length_prefixed_blobs(raw: bytes) -> list[bytes]:
    """Undo the length-prefixed packing used by :func:`decode_pvalue_to_bytes` for BlobArray."""
    blobs: list[bytes] = []
    pos = 0
    while pos + 4 <= len(raw):
        (length,) = struct.unpack_from(">I", raw, pos)
        pos += 4
        if pos + length > len(raw):
            raise S7ProtocolError("Truncated BlobArray payload in TextLibraryOffsetArea")
        blobs.append(raw[pos : pos + length])
        pos += length
    if pos != len(raw):
        raise S7ProtocolError("Trailing bytes in TextLibraryOffsetArea BlobArray")
    return blobs


def _read_entries(
    entry_table: bytes,
    string_table: bytes,
    entry_offset: int,
    decoded_texts: dict[int, str],
) -> list[TextListEntry]:
    entries = _try_read_entries(entry_table, string_table, entry_offset, decoded_texts, use_32bit=True)
    if entries is not None:
        return entries
    entries = _try_read_entries(entry_table, string_table, entry_offset, decoded_texts, use_32bit=False)
    if entries is None:
        raise S7ProtocolError(f"Cannot decode text-list entries at offset {entry_offset}")
    return entries


def _try_read_entries(
    entry_table: bytes,
    string_table: bytes,
    entry_offset: int,
    decoded_texts: dict[int, str],
    *,
    use_32bit: bool,
) -> Optional[list[TextListEntry]]:
    if entry_offset + 4 > len(entry_table):
        return None
    entry_count = _u32_le(entry_table, entry_offset)
    if entry_count > 0x7FFFFFFF:
        return None
    pos = entry_offset + 4
    record = 8 if use_32bit else 6
    if pos + entry_count * record > len(entry_table):
        return None
    entries: list[TextListEntry] = []
    for _ in range(entry_count):
        if use_32bit:
            value = struct.unpack_from("<i", entry_table, pos)[0]
            string_offset = _u32_le(entry_table, pos + 4)
            pos += 8
        else:
            value = struct.unpack_from("<H", entry_table, pos)[0]
            string_offset = _u32_le(entry_table, pos + 2)
            pos += 6
        text = _read_text(string_table, string_offset, decoded_texts)
        if text is None:
            return None
        entries.append(TextListEntry(value, value, text))
    return entries


def _read_text(string_table: bytes, offset: int, decoded_texts: dict[int, str]) -> Optional[str]:
    if offset in decoded_texts:
        return decoded_texts[offset]
    if offset + 2 > len(string_table):
        return None
    length = struct.unpack_from("<H", string_table, offset)[0]
    start = offset + 2
    if start + length > len(string_table):
        return None
    text = string_table[start : start + length].decode("utf-8", errors="replace")
    decoded_texts[offset] = text
    return text


def _parse_text_list_id(name: str) -> tuple[Optional[int], bool]:
    if not name or not name.strip():
        return None, False
    pos = 0
    list_id = 0
    while pos < len(name) and name[pos].isdigit():
        digit = ord(name[pos]) - 48
        if list_id > (0x7FFFFFFF - digit) // 10:
            return None, False
        list_id = list_id * 10 + digit
        pos += 1
    if pos == 0:
        return None, False
    has_legacy = pos + 1 == len(name) and name[pos] in ("W", "w")
    if pos < len(name) and not has_legacy:
        return None, False
    return list_id, has_legacy


def _u32_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]
