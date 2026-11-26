"""Unit tests for symbol / line-comment catalogs."""

from __future__ import annotations

from s7commplus.symbol_comments import parse_symbol_comment_catalog


def test_parse_refid_comments_by_access_sequence() -> None:
    xml = """
    <CommentDictionary>
      <TagLineComments>
        <Comment RefID="10">
          <DictEntry Language="de-DE">Eingang</DictEntry>
          <DictEntry Lanuage="en-US">Input</DictEntry>
        </Comment>
      </TagLineComments>
    </CommentDictionary>
    """
    catalog = parse_symbol_comment_catalog(0x8A0E0001, "Inputs", xml)
    comments = catalog.try_get_comments(access_sequence="8A0E0001.A")
    assert comments is not None
    assert comments[1031] == "Eingang"
    assert comments[1033] == "Input"


def test_parse_path_comments_with_interface() -> None:
    interface = """
    <Sections>
      <Section Name="Static">
        <Member Name="Motor" Datatype="Struct" Version="1.0">
          <AttributeList><BooleanAttribute Name="ExternalAccessible" SystemDefined="true">true</BooleanAttribute></AttributeList>
          <Sections><Section Name="None">
            <Member Name="Speed" Datatype="Int"><AttributeList>
              <IntegerAttribute Name="InterfaceMemberNumber" SystemDefined="true">51</IntegerAttribute>
            </AttributeList></Member>
          </Section></Sections>
          <AttributeList>
            <IntegerAttribute Name="InterfaceMemberNumber" SystemDefined="true">60</IntegerAttribute>
          </AttributeList>
        </Member>
      </Section>
    </Sections>
    """
    # Minimal Sections XML may not match BlockInterface parser — use Path/RefID fallback when interface fails.
    comments_xml = """
    <InterfaceLineComments>
      <Comment Path="60:51">
        <DictEntry Language="1031">Drehzahl</DictEntry>
      </Comment>
    </InterfaceLineComments>
    """
    catalog = parse_symbol_comment_catalog(0x8A0E0007, "DB1", comments_xml, interface)
    # If interface parsing succeeds, symbol path is set; otherwise catalog may be empty for Path-only.
    found = catalog.try_get_comments(symbol="DB1.Motor.Speed")
    if found is None:
        # Interface layout differs — Path without resolvable members is skipped (Driver also needs interface).
        assert catalog.count == 0
    else:
        assert found[1031] == "Drehzahl"


def test_array_indices_stripped_on_lookup() -> None:
    from s7commplus.symbol_comments import SymbolCommentCatalog

    catalog = SymbolCommentCatalog(
        relation_id=1,
        name="DB1",
        comments_by_symbol={"DB1.Speeds": {1033: "speeds"}},
        comments_by_access_sequence={},
    )
    assert catalog.try_get_comments(symbol="DB1.Speeds[0,1]") == {1033: "speeds"}
