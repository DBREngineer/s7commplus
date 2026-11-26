"""Symbol / block-interface comments from EXPLORE line-comment metadata.

Ports S7CommPlusDriver ``GetSymbolComments``: EXPLORE a relation for
``DataInterface_LineComments`` (+ interface description), decompress the
Siemens zlib blobs, and index comments by symbolic path or access sequence.
"""

from __future__ import annotations

import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Mapping, Optional, Protocol, Sequence

from .blob_decompressor import decompress_blob
from .block_interface import BlockInterface, resolve_id_path
from .codec import parse_or_raise_for_return_value
from .protocol import DataType, ElementID, FunctionCode, Ids
from .vlq import decode_uint32_vlq, encode_uint32_vlq

_ARRAY_INDEXES = re.compile(r"\[[^\]]*\]")

# Common TIA language tags → Windows LCID (matches LanguageId / Driver CultureInfo).
_LANGUAGE_TAGS: dict[str, int] = {
    "zh-tw": 1028,
    "cs-cz": 1029,
    "da-dk": 1030,
    "de-de": 1031,
    "el-gr": 1032,
    "en-us": 1033,
    "es-es": 1034,
    "fi-fi": 1035,
    "fr-fr": 1036,
    "hu-hu": 1038,
    "it-it": 1040,
    "ja-jp": 1041,
    "ko-kr": 1042,
    "nl-nl": 1043,
    "pl-pl": 1045,
    "pt-br": 1046,
    "ru-ru": 1049,
    "sv-se": 1053,
    "tr-tr": 1055,
    "zh-cn": 2052,
    "nl-be": 2067,
    "pt-pt": 2070,
}


@dataclass(frozen=True)
class SymbolCommentCatalog:
    """Localized engineering comments for one DB or absolute area relation."""

    relation_id: int
    name: str
    comments_by_symbol: Mapping[str, Mapping[int, str]]
    comments_by_access_sequence: Mapping[str, Mapping[int, str]]

    @property
    def count(self) -> int:
        return len(self.comments_by_symbol) + len(self.comments_by_access_sequence)

    def try_get_comments(
        self, *, symbol: str | None = None, access_sequence: str | None = None
    ) -> Optional[Mapping[int, str]]:
        """Lookup by declaration symbol (array indices stripped) or exact access sequence."""
        if symbol:
            key = _remove_array_indices(symbol)
            found = self.comments_by_symbol.get(key)
            if found:
                return found
        if access_sequence:
            for stored, comments in self.comments_by_access_sequence.items():
                if stored.lower() == access_sequence.lower():
                    return comments
        return None


class _CommentConnection(Protocol):
    def send_request(
        self, function_code: int, payload: bytes = b"", integrity_tail: int = 4, reassemble: bool = False
    ) -> bytes: ...


def build_symbol_comments_explore_payload(relation_id: int, *, with_integrity: bool = True) -> bytes:
    """EXPLORE payload for name + line comments + interface description."""
    from .client import _build_explore_request

    return _build_explore_request(
        relation_id & 0xFFFFFFFF,
        [
            Ids.OBJECT_VARIABLE_TYPE_NAME,
            Ids.DATA_INTERFACE_LINE_COMMENTS,
            Ids.DATA_INTERFACE_INTERFACE_DESCRIPTION,
        ],
        with_integrity=with_integrity,
    )


def parse_symbol_comment_catalog(
    relation_id: int,
    name: str,
    line_comments_xml: str,
    interface_description_xml: str = "",
) -> SymbolCommentCatalog:
    """Build a catalog from decompressed LineComm (+ optional interface) XML."""
    by_symbol: dict[str, dict[int, str]] = {}
    by_access: dict[str, dict[int, str]] = {}
    if not line_comments_xml.strip():
        return SymbolCommentCatalog(relation_id, name, by_symbol, by_access)

    root = ET.fromstring(line_comments_xml)
    members = ()
    if interface_description_xml.strip():
        try:
            members = BlockInterface.from_xml(interface_description_xml).members
        except (ValueError, ET.ParseError):
            members = ()

    for comment in root.iter():
        if _local_name(comment.tag) != "Comment":
            continue
        localized = _read_localized_comments(comment)
        if not localized:
            continue
        path = _attr(comment, "Path")
        if path and members:
            member_path = resolve_id_path(members, path)
            if member_path:
                symbol = f"{name}.{member_path}" if name else member_path
                by_symbol[symbol] = localized
                continue
        ref = _attr(comment, "RefID")
        ref_id = _parse_u32(ref) if ref else None
        if ref_id is not None:
            by_access[f"{relation_id:X}.{ref_id:X}"] = localized

    return SymbolCommentCatalog(relation_id, name, by_symbol, by_access)


def parse_symbol_comments_from_explore(response: bytes, relation_id: int) -> SymbolCommentCatalog:
    """Extract name/comments/interface from an EXPLORE reply and build a catalog."""
    offset = parse_or_raise_for_return_value(response, "Symbol comments")
    name = ""
    line_xml = ""
    interface_xml = ""

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
        if pos + 2 > len(response):
            offset = found + 1
            continue
        flags = response[pos]
        datatype = response[pos + 1]
        pos += 2
        try:
            if attr_id == Ids.OBJECT_VARIABLE_TYPE_NAME and datatype == DataType.WSTRING and flags == 0:
                length, consumed = decode_uint32_vlq(response, pos)
                start = pos + consumed
                name = response[start : start + length].decode("utf-8", errors="replace")
            elif attr_id == Ids.DATA_INTERFACE_LINE_COMMENTS and datatype == DataType.BLOB and flags == 0x40:
                blobs, _ = _decode_blob_sparse(response, pos)
                for key in sorted(blobs):
                    if blobs[key]:
                        line_xml = decompress_blob(blobs[key], offset=4)
                        break
            elif (
                attr_id == Ids.DATA_INTERFACE_INTERFACE_DESCRIPTION
                and datatype == DataType.BLOB
                and flags == 0
            ):
                payload, _ = _read_scalar_blob(response, pos)
                if payload:
                    interface_xml = decompress_blob(payload, offset=4)
        except (ValueError, IndexError, struct.error, OSError):
            pass
        offset = found + 1

    return parse_symbol_comment_catalog(relation_id, name, line_xml, interface_xml)


def read_symbol_comments(connection: _CommentConnection, relation_id: int) -> SymbolCommentCatalog:
    """Read symbol comments for one DB / absolute-area relation ID."""
    from .metadata import explore_integrity_framing

    with_integrity, integrity_tail = explore_integrity_framing(connection)  # type: ignore[arg-type]
    payload = build_symbol_comments_explore_payload(relation_id, with_integrity=with_integrity)
    response = connection.send_request(
        FunctionCode.EXPLORE, payload, integrity_tail=integrity_tail, reassemble=True
    )
    return parse_symbol_comments_from_explore(response, relation_id)


def _read_localized_comments(comment: ET.Element) -> dict[int, str]:
    result: dict[int, str] = {}
    for entry in comment.iter():
        if _local_name(entry.tag) != "DictEntry":
            continue
        language = _attr(entry, "Language") or _attr(entry, "Lanuage")
        language_id = _language_id(language)
        text = (entry.text or "").strip()
        if language_id is None or not text:
            continue
        result[language_id] = entry.text or ""
    return result


def _language_id(language: str | None) -> Optional[int]:
    if not language:
        return None
    text = language.strip()
    if text.isdigit():
        return int(text)
    return _LANGUAGE_TAGS.get(text.lower())


def _remove_array_indices(symbol: str) -> str:
    return _ARRAY_INDEXES.sub("", symbol)


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _attr(element: ET.Element, name: str) -> Optional[str]:
    for key, value in element.attrib.items():
        if _local_name(key).lower() == name.lower():
            return value
    return None


def _parse_u32(value: str) -> Optional[int]:
    text = value.strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _decode_blob_sparse(data: bytes, offset: int) -> tuple[dict[int, bytes], int]:
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
        blobs[key] = data[offset : offset + length]
        offset += length
    return blobs, offset


def _read_scalar_blob(data: bytes, offset: int) -> tuple[bytes, int]:
    _root, consumed = decode_uint32_vlq(data, offset)
    offset += consumed
    length, consumed = decode_uint32_vlq(data, offset)
    offset += consumed
    return data[offset : offset + length], offset + length
