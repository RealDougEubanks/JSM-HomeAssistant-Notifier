"""Tests for JSMClient methods."""

from __future__ import annotations

import time

import httpx
import pytest
import respx

from src.jsm_client import JSMClient


@pytest.fixture
def client() -> JSMClient:
    return JSMClient(
        api_url="https://api.atlassian.com",
        cloud_id="cloud-123",
        username="user@example.com",
        api_token="tok",
        my_user_id="user-42",
    )


def _sched_url(c: JSMClient) -> str:
    return f"{c.api_url}/jsm/ops/api/{c.cloud_id}/v1/schedules"


# ── get_all_schedules ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_all_schedules_single_page(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(
            return_value=httpx.Response(
                200, json={"values": [{"id": "s1", "name": "A"}], "paging": {}}
            )
        )
        result = await client.get_all_schedules()
    assert result == [{"id": "s1", "name": "A"}]


@pytest.mark.asyncio
async def test_get_all_schedules_empty(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(
            return_value=httpx.Response(200, json={"values": [], "paging": {}})
        )
        result = await client.get_all_schedules()
    assert result == []


# ── get_schedule_id ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_schedule_id_found(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(
            return_value=httpx.Response(
                200,
                json={"values": [{"id": "s1", "name": "MySchedule"}], "paging": {}},
            )
        )
        sid = await client.get_schedule_id("MySchedule")
    assert sid == "s1"


@pytest.mark.asyncio
async def test_get_schedule_id_cached(client: JSMClient):
    client._schedule_id_cache["Cached"] = "c1"
    sid = await client.get_schedule_id("Cached")
    assert sid == "c1"


@pytest.mark.asyncio
async def test_get_schedule_id_not_found(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(
            return_value=httpx.Response(200, json={"values": [], "paging": {}})
        )
        sid = await client.get_schedule_id("Missing")
    assert sid is None


@pytest.mark.asyncio
async def test_get_schedule_id_api_error(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(side_effect=httpx.ConnectError("nope"))
        sid = await client.get_schedule_id("Any")
    assert sid is None


# ── is_on_call ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_is_on_call_true(client: JSMClient):
    oncall_url = f"{_sched_url(client)}/s1/on-calls"
    with respx.mock:
        respx.get(oncall_url).mock(
            return_value=httpx.Response(
                200, json={"onCallParticipants": [{"id": "user-42", "type": "user"}]}
            )
        )
        assert await client.is_on_call("s1") is True


@pytest.mark.asyncio
async def test_is_on_call_false(client: JSMClient):
    oncall_url = f"{_sched_url(client)}/s1/on-calls"
    with respx.mock:
        respx.get(oncall_url).mock(
            return_value=httpx.Response(
                200, json={"onCallParticipants": [{"id": "other", "type": "user"}]}
            )
        )
        assert await client.is_on_call("s1") is False


@pytest.mark.asyncio
async def test_is_on_call_true_via_nested_team(client: JSMClient):
    """User reached through escalation → team nesting is detected as on-call."""
    oncall_url = f"{_sched_url(client)}/s1/on-calls"
    nested_response = {
        "onCallParticipants": [
            {
                "id": "esc-1",
                "type": "escalation",
                "onCallParticipants": [
                    {
                        "id": "team-1",
                        "type": "team",
                        "onCallParticipants": [
                            {"id": "user-42", "type": "user"},
                            {"id": "other-user", "type": "user"},
                        ],
                    }
                ],
            }
        ]
    }
    with respx.mock:
        respx.get(oncall_url).mock(return_value=httpx.Response(200, json=nested_response))
        assert await client.is_on_call("s1") is True


@pytest.mark.asyncio
async def test_is_on_call_cache_hit(client: JSMClient):
    client._oncall_cache["s1"] = (True, time.monotonic())
    assert await client.is_on_call("s1", cache_ttl=300) is True


@pytest.mark.asyncio
async def test_is_on_call_api_error_fail_open(client: JSMClient):
    oncall_url = f"{_sched_url(client)}/s1/on-calls"
    with respx.mock:
        respx.get(oncall_url).mock(side_effect=httpx.ConnectError("down"))
        assert await client.is_on_call("s1") is True


# ── verify_credentials ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_credentials_ok(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(
            return_value=httpx.Response(200, json={"values": [{"id": "s1"}]})
        )
        ok, err = await client.verify_credentials()
    assert ok is True and err == ""


@pytest.mark.asyncio
async def test_verify_credentials_401(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(return_value=httpx.Response(401))
        ok, err = await client.verify_credentials()
    assert ok is False and "401" in err


@pytest.mark.asyncio
async def test_verify_credentials_403(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(return_value=httpx.Response(403))
        ok, err = await client.verify_credentials()
    assert ok is False and "403" in err


@pytest.mark.asyncio
async def test_verify_credentials_500(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(return_value=httpx.Response(500))
        ok, err = await client.verify_credentials()
    assert ok is False and "500" in err


@pytest.mark.asyncio
async def test_verify_credentials_connection_error(client: JSMClient):
    with respx.mock:
        respx.get(_sched_url(client)).mock(side_effect=httpx.ConnectError("down"))
        ok, err = await client.verify_credentials()
    assert ok is False and "Connection error" in err


# ── acknowledge_alert ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_acknowledge_alert_success(client: JSMClient):
    url = f"{client.api_url}/jsm/ops/api/{client.cloud_id}/v1/alerts/a1/acknowledge"
    with respx.mock:
        respx.post(url).mock(return_value=httpx.Response(202))
        ok, err = await client.acknowledge_alert("a1")
    assert ok is True and err == ""


@pytest.mark.asyncio
async def test_acknowledge_alert_http_error(client: JSMClient):
    url = f"{client.api_url}/jsm/ops/api/{client.cloud_id}/v1/alerts/a1/acknowledge"
    with respx.mock:
        respx.post(url).mock(return_value=httpx.Response(404, text="Not found"))
        ok, err = await client.acknowledge_alert("a1")
    assert ok is False and "404" in err


@pytest.mark.asyncio
async def test_acknowledge_alert_connection_error(client: JSMClient):
    url = f"{client.api_url}/jsm/ops/api/{client.cloud_id}/v1/alerts/a1/acknowledge"
    with respx.mock:
        respx.post(url).mock(side_effect=httpx.ConnectError("gone"))
        ok, err = await client.acknowledge_alert("a1")
    assert ok is False


# ── get_alert_details ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_alert_details_success(client: JSMClient):
    url = f"{client.api_url}/jsm/ops/api/{client.cloud_id}/v1/alerts/a1"
    with respx.mock:
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"data": {"id": "a1", "message": "hi"}})
        )
        result = await client.get_alert_details("a1")
    assert result == {"id": "a1", "message": "hi"}


@pytest.mark.asyncio
async def test_get_alert_details_failure(client: JSMClient):
    url = f"{client.api_url}/jsm/ops/api/{client.cloud_id}/v1/alerts/a1"
    with respx.mock:
        respx.get(url).mock(side_effect=httpx.ConnectError("down"))
        result = await client.get_alert_details("a1")
    assert result is None


# ── list_open_alerts ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_open_alerts_success(client: JSMClient):
    url = f"{client.api_url}/jsm/ops/api/{client.cloud_id}/v1/alerts"
    with respx.mock:
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"data": [{"id": "a1"}, {"id": "a2"}]})
        )
        result = await client.list_open_alerts()
    assert len(result) == 2


@pytest.mark.asyncio
async def test_list_open_alerts_failure(client: JSMClient):
    url = f"{client.api_url}/jsm/ops/api/{client.cloud_id}/v1/alerts"
    with respx.mock:
        respx.get(url).mock(side_effect=httpx.ConnectError("nope"))
        result = await client.list_open_alerts()
    assert result == []


# ── invalidate_oncall_cache ──────────────────────────────────────────────────


def test_invalidate_oncall_cache(client: JSMClient):
    client._oncall_cache["s1"] = (True, 0.0)
    client.invalidate_oncall_cache()
    assert client._oncall_cache == {}
