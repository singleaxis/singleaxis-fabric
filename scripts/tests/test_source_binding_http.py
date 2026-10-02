"""TLS qualifier credentials must stay at the exact operator destination."""

import io
import ssl
from email.message import Message
from urllib.request import HTTPSHandler
from urllib.response import addinfourl

import pytest

pytest.importorskip("grpc", reason="source-binding probe requires grpcio test extra")

from scripts.qualification import check_source_binding as qualifier  # noqa: E402


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/v1/logs",
        "https://user:password@localhost/v1/logs",
        "https://localhost/v1/logs#fragment",
        "https:///v1/logs",
        "https://localhost:bad/v1/logs",
        "https://localhost:0/v1/logs",
        "https://localhost/v1/logs#",
    ],
)
def test_invalid_destination_never_builds_transport(monkeypatch, url):
    def unexpected(*args, **kwargs):
        raise AssertionError("transport was constructed")

    monkeypatch.setattr(qualifier, "build_opener", unexpected)
    with pytest.raises(ValueError):
        qualifier._http(url, b"", ssl.create_default_context(), "Bearer SYNTHETIC")


def fake_transport(monkeypatch, status, payload, redirect=None):
    calls = []
    contexts = []

    class Transport(HTTPSHandler):
        def __init__(self, *, context):
            super().__init__(context=context)
            contexts.append(context)

        def https_open(self, request):
            calls.append((request.full_url, request.get_header("Authorization")))
            headers = Message()
            if redirect:
                headers["Location"] = redirect
            response = addinfourl(
                io.BytesIO(payload), headers, request.full_url, status
            )
            response.msg = "fixture"
            return response

    monkeypatch.setattr(qualifier, "HTTPSHandler", Transport)
    return calls, contexts


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_does_not_forward_credentials(monkeypatch, status):
    calls, _ = fake_transport(monkeypatch, status, b"", "https://other.invalid/v1/logs")
    result = qualifier._http(
        "https://original.invalid/v1/logs",
        b"",
        ssl.create_default_context(),
        "Bearer SYNTHETIC",
    )
    assert result == (status, 0)
    assert calls == [("https://original.invalid/v1/logs", "Bearer SYNTHETIC")]


def test_valid_destination_preserves_tls_context_and_response(monkeypatch):
    response = qualifier.ExportLogsServiceResponse()
    response.partial_success.rejected_log_records = 2
    calls, contexts = fake_transport(monkeypatch, 200, response.SerializeToString())
    context = ssl.create_default_context()
    assert qualifier._http(
        "https://original.invalid/v1/logs", b"", context, "Bearer SYNTHETIC"
    ) == (200, 2)
    assert contexts == [context]
    assert len(calls) == 1


@pytest.mark.parametrize("status", [200, 400])
def test_response_and_error_bodies_are_bounded(monkeypatch, status):
    monkeypatch.setattr(qualifier, "MAX_HTTP_RESPONSE_BYTES", 32)
    fake_transport(monkeypatch, status, b"x" * 33)
    with pytest.raises(ValueError, match="bounded"):
        qualifier._http(
            "https://original.invalid/v1/logs",
            b"",
            ssl.create_default_context(),
            "Bearer SYNTHETIC",
        )
