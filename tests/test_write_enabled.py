"""WriteEnabled safety gate (matches S7CommPlusDriver)."""

from __future__ import annotations

import pytest

from s7commplus import AsyncClient, Client, S7WriteDisabledError


@pytest.mark.write_gate
class TestWriteEnabledGate:
    def test_default_is_disabled(self) -> None:
        assert Client().write_enabled is False
        assert AsyncClient().write_enabled is False

    def test_sync_write_tags_blocked(self) -> None:
        client = Client()
        with pytest.raises(S7WriteDisabledError, match="write_enabled"):
            client.write_tags({"Tag": b"\x00"})

    def test_sync_db_write_multi_blocked(self) -> None:
        client = Client()
        with pytest.raises(S7WriteDisabledError, match="write_enabled"):
            client.db_write_multi([(1, 0, b"\x00")])

    def test_sync_write_area_blocked(self) -> None:
        client = Client()
        with pytest.raises(S7WriteDisabledError, match="write_enabled"):
            client.write_area(1, 0, b"\x00")

    def test_sync_write_symbolic_blocked(self) -> None:
        client = Client()
        with pytest.raises(S7WriteDisabledError, match="write_enabled"):
            client.write_symbolic(0x8A0E0000, [1], b"\x00")

    def test_sync_operating_state_blocked(self) -> None:
        client = Client()
        with pytest.raises(S7WriteDisabledError, match="write_enabled"):
            client.request_operating_state(1)

    @pytest.mark.asyncio
    async def test_async_write_tags_blocked(self) -> None:
        client = AsyncClient()
        with pytest.raises(S7WriteDisabledError, match="write_enabled"):
            await client.write_tags({"Tag": b"\x00"})

    @pytest.mark.asyncio
    async def test_async_db_write_multi_blocked(self) -> None:
        client = AsyncClient()
        with pytest.raises(S7WriteDisabledError, match="write_enabled"):
            await client.db_write_multi([(1, 0, b"\x00")])

    @pytest.mark.asyncio
    async def test_async_operating_state_blocked(self) -> None:
        client = AsyncClient()
        with pytest.raises(S7WriteDisabledError, match="write_enabled"):
            await client.request_operating_state(1)
