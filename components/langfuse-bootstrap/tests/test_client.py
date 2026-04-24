# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64

import httpx
import pytest
import respx

from fabric_langfuse_bootstrap.client import LangfuseBootstrapClient, LangfuseError
from fabric_langfuse_bootstrap.config import ScoreConfig, ScoreDataType

HOST = "http://langfuse.test"
PK = "pk-lf-test"
SK = "sk-lf-test"
EXPECTED_AUTH = "Basic " + base64.b64encode(f"{PK}:{SK}".encode()).decode("ascii")


@pytest.fixture
def client() -> LangfuseBootstrapClient:
    return LangfuseBootstrapClient(host=HOST, public_key=PK, secret_key=SK)


@respx.mock
def test_health_ok(client: LangfuseBootstrapClient) -> None:
    route = respx.get(f"{HOST}/api/public/health").mock(
        return_value=httpx.Response(200, json={"status": "OK"})
    )
    assert client.health() is True
    assert route.called
    assert route.calls[-1].request.headers["authorization"] == EXPECTED_AUTH


@respx.mock
def test_health_failure(client: LangfuseBootstrapClient) -> None:
    respx.get(f"{HOST}/api/public/health").mock(return_value=httpx.Response(503))
    assert client.health() is False


@respx.mock
def test_apply_score_config_creates_when_missing(client: LangfuseBootstrapClient) -> None:
    respx.get(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    create = respx.post(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(
            200,
            json={"id": "sc_1", "name": "groundedness", "dataType": "NUMERIC"},
        )
    )

    cfg = ScoreConfig(
        name="groundedness",
        data_type=ScoreDataType.NUMERIC,
        min_value=0.0,
        max_value=1.0,
        description="test",
    )
    out = client.apply_score_config(cfg)

    assert create.called
    payload = create.calls[-1].request.read()
    assert b'"name":"groundedness"' in payload
    assert b'"dataType":"NUMERIC"' in payload
    assert b'"minValue":0.0' in payload
    assert b'"maxValue":1.0' in payload
    assert out["id"] == "sc_1"


@respx.mock
def test_apply_score_config_skips_when_present(client: LangfuseBootstrapClient) -> None:
    respx.get(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": "sc_existing", "name": "groundedness", "dataType": "NUMERIC"}]},
        )
    )
    create_route = respx.post(f"{HOST}/api/public/score-configs")

    cfg = ScoreConfig(name="groundedness", data_type=ScoreDataType.NUMERIC)
    out = client.apply_score_config(cfg)

    assert out["id"] == "sc_existing"
    assert not create_route.called


@respx.mock
def test_apply_score_config_raises_on_api_error(client: LangfuseBootstrapClient) -> None:
    respx.get(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.post(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(401, text="bad auth")
    )

    cfg = ScoreConfig(name="x", data_type=ScoreDataType.NUMERIC)
    with pytest.raises(LangfuseError) as exc:
        client.apply_score_config(cfg)
    assert exc.value.status_code == 401
    assert "bad auth" in exc.value.body


@respx.mock
def test_apply_prompt_creates_when_missing(client: LangfuseBootstrapClient) -> None:
    respx.get(f"{HOST}/api/public/v2/prompts/my-prompt").mock(return_value=httpx.Response(404))
    create = respx.post(f"{HOST}/api/public/v2/prompts").mock(
        return_value=httpx.Response(200, json={"name": "my-prompt", "version": 1})
    )

    out = client.apply_prompt(name="my-prompt", prompt="hello")
    assert create.called
    assert out["version"] == 1


@respx.mock
def test_apply_prompt_skips_when_identical(client: LangfuseBootstrapClient) -> None:
    respx.get(f"{HOST}/api/public/v2/prompts/my-prompt").mock(
        return_value=httpx.Response(
            200, json={"name": "my-prompt", "prompt": "hello", "version": 3}
        )
    )
    create_route = respx.post(f"{HOST}/api/public/v2/prompts")

    out = client.apply_prompt(name="my-prompt", prompt="hello")
    assert out["version"] == 3
    assert not create_route.called


@respx.mock
def test_apply_prompt_creates_new_version_when_text_changed(
    client: LangfuseBootstrapClient,
) -> None:
    respx.get(f"{HOST}/api/public/v2/prompts/my-prompt").mock(
        return_value=httpx.Response(
            200, json={"name": "my-prompt", "prompt": "old text", "version": 3}
        )
    )
    create = respx.post(f"{HOST}/api/public/v2/prompts").mock(
        return_value=httpx.Response(200, json={"name": "my-prompt", "version": 4})
    )

    out = client.apply_prompt(name="my-prompt", prompt="new text")
    assert create.called
    assert out["version"] == 4


def test_saved_view_url_is_deterministic(client: LangfuseBootstrapClient) -> None:
    url_a = client.render_saved_view_url({"a": "1", "b": "2"})
    url_b = client.render_saved_view_url({"b": "2", "a": "1"})
    assert url_a == url_b
    assert "a%3D1%3Bb%3D2" in url_a  # a=1;b=2 URL-encoded
