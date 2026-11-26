"""Unit tests for hierarchical BrowseNode helpers."""

from __future__ import annotations

from s7commplus.block_interface import Member
from s7commplus.symbol_browser import (
    BrowseNode,
    SymbolBrowser,
    members_to_browse_nodes,
    quote_symbol_segment,
    split_symbol_path,
    unquote_segment,
)


def test_quote_and_split_dotted_db_names() -> None:
    assert quote_symbol_segment("SC.GC.db_Alarm") == '"SC.GC.db_Alarm"'
    assert split_symbol_path('"SC.GC.db_Alarm".Motor.Speed') == ['"SC.GC.db_Alarm"', "Motor", "Speed"]
    assert unquote_segment('"SC.GC.db_Alarm"') == "SC.GC.db_Alarm"


def test_members_to_browse_nodes() -> None:
    members = [
        Member(name="Flag", data_type="Bool", lid=1, offset=0, rid=1, id=10),
        Member(
            name="Motor",
            data_type="Struct",
            lid=2,
            offset=2,
            rid=2,
            id=20,
            fields=[Member(name="Speed", data_type="Int", lid=3, offset=0, rid=5, id=51)],
        ),
    ]
    nodes = members_to_browse_nodes(members, parent_path="DB1", relation_id=0x8A0E0001)
    assert nodes[0].name == "Flag"
    assert nodes[0].symbol_path == "DB1.Flag"
    assert nodes[0].has_children is False
    assert nodes[0].access_sequence == "8A0E0001.A"
    assert nodes[1].name == "Motor"
    assert nodes[1].has_children is True
    assert nodes[1].is_structure is True


def test_symbol_browser_top_level_and_expand() -> None:
    class _DB:
        def __init__(self, name: str, rid: int) -> None:
            self.name = name
            self.rid = rid

    class _Client:
        def list_datablocks(self):
            return [_DB("DB1", 0x8A0E0001)]

        def explore(self, explore_id=0, attributes=None):
            raise AssertionError("not used in this unit test")

    browser = SymbolBrowser(_Client())
    # Inject interface without explore
    from s7commplus.block_interface import BlockInterface

    interface = BlockInterface(
        members=[
            Member(name="Flag", data_type="Bool", lid=1, offset=0, rid=1, id=10),
        ],
        source=None,
        references=frozenset(),
    )
    browser._interface_cache[0x8A0E0001] = interface
    roots = browser.browse_node()
    assert len(roots) == 1
    assert roots[0].symbol_path == "DB1"
    children = browser.browse_node("DB1")
    assert children[0].name == "Flag"
    assert browser.clear_cache() is True
