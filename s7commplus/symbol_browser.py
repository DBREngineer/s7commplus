"""One-level hierarchical symbol browser (BrowseNode).

Ports the essential surface of S7CommPlusDriver ``S7CommPlusSymbolBrowser``:
list data blocks as roots, then expand one level of a DB interface via the
already-ported :class:`~s7commplus.block_interface.BlockInterface` XML.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional, Protocol, Sequence

from .block_interface import Member, SOFTDATATYPE, BlockInterface, _ARRAY_PREFIX
from .protocol import Ids

_QUOTED_SEGMENT = re.compile(r'^"(.*)"$')
_SOFTDATATYPE_BY_NAME = {name: code for code, name in SOFTDATATYPE.items()}
_SOFTDATATYPE_BY_NAME.setdefault("Struct", next((k for k, v in SOFTDATATYPE.items() if v == "Struct"), 0))


@dataclass(frozen=True)
class BrowseNode:
    """One direct child of a lazily browsed PLC data-block interface."""

    name: str
    symbol_path: str
    softdatatype: int = 0
    is_structure: bool = False
    native_type_name: str = ""
    has_children: bool = False
    is_array: bool = False
    array_dimension: Optional[int] = None
    string_length: Optional[int] = None
    access_sequence: Optional[str] = None
    relation_id: Optional[int] = None


class _BrowseClient(Protocol):
    def list_datablocks(self) -> Sequence[Any]: ...

    def explore(self, explore_id: int = 0, attributes: Sequence[int] | None = None) -> bytes: ...


def quote_symbol_segment(name: str) -> str:
    """Quote a DB/member name when it contains dots (Driver BrowseNode convention)."""
    if "." in name and not (name.startswith('"') and name.endswith('"')):
        return f'"{name}"'
    return name


def split_symbol_path(symbol_path: str) -> list[str]:
    """Split a browsed path into segments, honouring quoted identifiers."""
    segments: list[str] = []
    buf: list[str] = []
    in_quotes = False
    for ch in symbol_path:
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif ch == "." and not in_quotes:
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        segments.append("".join(buf))
    return segments


def unquote_segment(segment: str) -> str:
    matched = _QUOTED_SEGMENT.fullmatch(segment)
    return matched.group(1) if matched else segment


def members_to_browse_nodes(
    members: Sequence[Member],
    *,
    parent_path: str,
    relation_id: int | None = None,
    parent_access: str | None = None,
) -> list[BrowseNode]:
    """Convert one level of interface members into browse nodes."""
    nodes: list[BrowseNode] = []
    for member in members:
        child_path = f"{parent_path}.{quote_symbol_segment(member.name)}" if parent_path else quote_symbol_segment(member.name)
        is_array = bool(_ARRAY_PREFIX.match(member.data_type))
        has_fields = bool(member.fields)
        is_struct = has_fields or member.data_type.endswith("Struct") or bool(member.referenced_type)
        soft = _soft_for_type(member.element_type if not is_struct else "Struct", is_struct)
        access = None
        if parent_access is not None and member.id:
            access = f"{parent_access}.{member.id:X}"
        elif relation_id is not None and member.id and not has_fields and not is_array:
            access = f"{relation_id:X}.{member.id:X}"
        nodes.append(
            BrowseNode(
                name=member.name,
                symbol_path=child_path,
                softdatatype=soft,
                is_structure=is_struct and not is_array,
                native_type_name=member.data_type,
                has_children=has_fields or is_array or bool(member.referenced_type),
                is_array=is_array,
                array_dimension=_one_dim_count(member.data_type) if is_array else None,
                string_length=_string_length(member.data_type),
                access_sequence=access,
                relation_id=relation_id,
            )
        )
    return nodes


class SymbolBrowser:
    """Lazy one-level browser over PLC data-block interfaces."""

    def __init__(self, client: _BrowseClient) -> None:
        self._client = client
        self._db_cache: list[Any] | None = None
        self._interface_cache: dict[int, BlockInterface] = {}

    def clear_cache(self) -> bool:
        """Drop cached DB list and interfaces. Returns whether anything was cached."""
        had = self._db_cache is not None or bool(self._interface_cache)
        self._db_cache = None
        self._interface_cache.clear()
        return had

    def browse_node(self, symbol_path: str | None = None) -> list[BrowseNode]:
        """Return direct children under ``symbol_path`` (or DB roots when empty)."""
        dbs = self._dbs()
        if not symbol_path:
            return [
                BrowseNode(
                    name=db.name,
                    symbol_path=quote_symbol_segment(db.name),
                    softdatatype=_SOFTDATATYPE_BY_NAME.get("Struct", 0),
                    is_structure=True,
                    native_type_name="DB",
                    has_children=True,
                    relation_id=int(db.rid),
                )
                for db in dbs
            ]

        segments = split_symbol_path(symbol_path)
        db, db_segments = self._find_db(dbs, segments)
        interface = self._interface(int(db.rid))
        members = interface.members
        # Walk remaining member segments.
        walked = segments[db_segments:]
        parent_path = quote_symbol_segment(db.name)
        for segment in walked:
            name = unquote_segment(segment)
            match = next((m for m in members if m.name == name), None)
            if match is None:
                raise KeyError(f"Member {name!r} not found under {parent_path}")
            parent_path = f"{parent_path}.{quote_symbol_segment(match.name)}"
            members = match.fields
            if not members and match.referenced_type:
                # System/UDT types without embedded fields: no further children here.
                return []
        return members_to_browse_nodes(members, parent_path=parent_path, relation_id=int(db.rid))

    def _dbs(self) -> list[Any]:
        if self._db_cache is None:
            self._db_cache = list(self._client.list_datablocks())
        return self._db_cache

    def _interface(self, relation_id: int) -> BlockInterface:
        cached = self._interface_cache.get(relation_id)
        if cached is not None:
            return cached
        raw = self._client.explore(relation_id, [Ids.DATA_INTERFACE_INTERFACE_DESCRIPTION])
        interface = BlockInterface.from_explore(raw)
        self._interface_cache[relation_id] = interface
        return interface

    def _find_db(self, dbs: Sequence[Any], segments: list[str]) -> tuple[Any, int]:
        """Match the longest DB name prefix (supports dotted DB names)."""
        for count in range(len(segments), 0, -1):
            candidate = ".".join(unquote_segment(s) for s in segments[:count])
            # Also try quoted single-segment form.
            if count == 1:
                candidate = unquote_segment(segments[0])
            for db in dbs:
                if db.name == candidate:
                    return db, count
        raise KeyError(f"Data block {unquote_segment(segments[0])!r} not found")


def _soft_for_type(data_type: str, is_struct: bool) -> int:
    if is_struct:
        return _SOFTDATATYPE_BY_NAME.get("Struct", 0)
    bare = _ARRAY_PREFIX.sub("", data_type).strip().strip('"')
    return _SOFTDATATYPE_BY_NAME.get(bare, 0)


def _one_dim_count(data_type: str) -> Optional[int]:
    matched = re.match(r"Array\[(-?\d+)\.\.(-?\d+)\] of ", data_type)
    if not matched or "," in data_type[matched.start() : matched.end()]:
        return None
    low, high = int(matched.group(1)), int(matched.group(2))
    return high - low + 1


def _string_length(data_type: str) -> Optional[int]:
    matched = re.fullmatch(r"(?:W)?String\[(\d+)\]", data_type, flags=re.IGNORECASE)
    if matched:
        return int(matched.group(1))
    return None
