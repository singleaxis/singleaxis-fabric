# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Behavioral evidence for owner-private spool setup and verified stdlib TLS."""

from __future__ import annotations

import datetime
import ipaddress
import json
import multiprocessing
import os
import ssl
import stat
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fabric import ContentCaptureConfig, ContentWriter, LocalFilesystemContentStore
from fabric.http_dispatch import FinalHTTPAdapter
from fabric.metadata_delivery import HTTPMetadataTransport
from fabric.synthetic_otlp import _export_projected_metadata


def _config(root: Path, spool: Path) -> ContentCaptureConfig:
    return ContentCaptureConfig(
        store=LocalFilesystemContentStore(str(root / "store"), tenant_id="tenant"),
        roles="all",
        durability="spooled",
        spool_dir=str(spool),
    )


@pytest.mark.parametrize("ineffective", [False, True])
def test_spool_permission_failure_aborts_before_recovery_or_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ineffective: bool
) -> None:
    spool = tmp_path / "spool"
    spool.mkdir(mode=0o755)
    spool.chmod(0o755)
    started: list[str] = []
    monkeypatch.setattr(ContentWriter, "_recover_spool", lambda _: started.append("recovery"))
    monkeypatch.setattr(threading.Thread, "start", lambda _: started.append("worker"))

    def refuse(_fd: int, _mode: int) -> None:
        if not ineffective:
            raise PermissionError("synthetic permission refusal")

    monkeypatch.setattr(os, "fchmod", refuse)
    with pytest.raises(PermissionError):
        ContentWriter(_config(tmp_path, spool))
    assert started == []
    assert list(spool.iterdir()) == []


@pytest.mark.parametrize("ancestor", [False, True])
def test_spool_symlink_refused_without_touching_target(tmp_path: Path, ancestor: bool) -> None:
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    outside.chmod(0o755)
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    spool = alias / "new-spool" if ancestor else alias
    with pytest.raises(OSError):
        ContentWriter(_config(tmp_path, spool))
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("path", ["/", "/tmp/../"])
def test_spool_cannot_change_root_or_traversal_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("unsafe permission operation reached")

    monkeypatch.setattr(os, "chmod", forbidden)
    monkeypatch.setattr(os, "fchmod", forbidden)
    with pytest.raises(ValueError, match="dedicated directory"):
        ContentWriter(_config(tmp_path, Path(path)))


def _observe_private_spool_creation(root: Path) -> None:
    # An isolated child keeps the permissive umask out of the test runner.
    modes: list[int] = []
    real_mkdir = os.mkdir
    original_umask = os.umask(0)

    def mkdir(path: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
        real_mkdir(path, mode, dir_fd=dir_fd)
        modes.append(stat.S_IMODE(os.stat(path, dir_fd=dir_fd).st_mode))

    os.mkdir = mkdir
    try:
        writer = ContentWriter(_config(root, root / "nested" / "spool"))
        writer.close()
    finally:
        os.mkdir = real_mkdir
        os.umask(original_umask)
    (root / "created-modes.json").write_text(json.dumps(modes))


def test_spool_created_privately_before_chmod_under_permissive_umask(tmp_path: Path) -> None:
    child = multiprocessing.get_context("spawn").Process(
        target=_observe_private_spool_creation, args=(tmp_path,)
    )
    child.start()
    child.join(10)
    try:
        assert child.exitcode == 0
        assert json.loads((tmp_path / "created-modes.json").read_text()) == [0o700, 0o700]
    finally:
        if child.is_alive():
            child.terminate()
            child.join(2)


def _certificate(
    root: Path,
    name: str,
    *,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
    server: bool = False,
) -> tuple[Path, Path, x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    is_ca = issuer_cert is None
    signing_key = issuer_key or key
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject if issuer_cert is None else issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=not is_ca,
                content_commitment=False,
                key_encipherment=not is_ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
    )
    if not is_ca:
        purpose = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = builder.add_extension(x509.ExtendedKeyUsage([purpose]), False)
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            False,
        )
    cert = builder.sign(signing_key, hashes.SHA256())
    cert_path, key_path = root / (name + ".crt"), root / (name + ".key")
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.touch(mode=0o600)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, cert, key


@pytest.fixture
def tls_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    default_context = ssl.create_default_context

    def strict_context(*args: Any, **kwargs: Any) -> ssl.SSLContext:
        context = default_context(*args, **kwargs)
        # Exercise Python 3.13's stricter chain validation on older runtimes too.
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        return context

    monkeypatch.setattr(ssl, "create_default_context", strict_context)
    ca_path, _, ca, ca_key = _certificate(tmp_path, "ca")
    server_cert, server_key, _, _ = _certificate(
        tmp_path, "server", issuer_cert=ca, issuer_key=ca_key, server=True
    )
    client_cert, client_key, _, _ = _certificate(
        tmp_path, "client", issuer_cert=ca, issuer_key=ca_key
    )
    untrusted_ca, _, _, _ = _certificate(tmp_path, "untrusted")
    requests: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def do_POST(self) -> None:
            requests.append(
                {
                    "path": self.path,
                    "body": self.rfile.read(int(self.headers["Content-Length"])),
                    "peer": self.connection.getpeercert(),
                }
            )
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(server_cert, server_key)
    context.load_verify_locations(cafile=ca_path)
    context.verify_mode = ssl.CERT_OPTIONAL
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "port": server.server_port,
            "ca": ca_path,
            "untrusted_ca": untrusted_ca,
            "client_cert": client_cert,
            "client_key": client_key,
            "requests": requests,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def _send_tls(
    adapter: str, service: dict[str, Any], fault: str, monkeypatch: pytest.MonkeyPatch
) -> object:
    host = "localhost" if fault == "hostname" else "127.0.0.1"
    endpoint = f"https://{host}:{service['port']}/v1/logs"
    ca = service["untrusted_ca"] if fault == "untrusted" else service["ca"]
    if adapter == "dispatch":
        monkeypatch.setenv("SSL_CERT_FILE", str(ca))
        client = FinalHTTPAdapter(declared_url=endpoint, timeout_s=1)
        return client.request("POST", endpoint, b"{}", operation_id="op", attempt_id="attempt")
    tls_args = {
        "ca_cert_path": str(ca),
        "client_cert_path": str(service["client_cert"]),
        "client_key_path": str(service["client_key"]),
    }
    if adapter == "metadata":
        transport = HTTPMetadataTransport(
            endpoint, tenant_id="tenant", run_id="run", scope="scope", timeout_s=1, **tls_args
        )
        return transport.send(b"{}", "batch")
    return _export_projected_metadata(b"{}", [], endpoint, timeout_s=1, **tls_args)


@pytest.mark.parametrize("adapter", ["dispatch", "metadata", "synthetic"])
@pytest.mark.parametrize("fault", ["none", "untrusted", "hostname"])
def test_stdlib_https_verifies_certificate_chain_and_hostname(
    tls_server: dict[str, Any], monkeypatch: pytest.MonkeyPatch, adapter: str, fault: str
) -> None:
    # Direct connections deliberately do not adopt ambient proxy routing.
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    if fault == "none":
        _send_tls(adapter, tls_server, fault, monkeypatch)
        assert len(tls_server["requests"]) == 1
        assert tls_server["requests"][0]["body"] == b"{}"
        if adapter != "dispatch":
            assert tls_server["requests"][0]["peer"]
    elif adapter == "synthetic":
        # The offline exporter deliberately sanitizes transport failures.
        with pytest.raises(ValueError, match=r"^OTLP metadata export failed$"):
            _send_tls(adapter, tls_server, fault, monkeypatch)
        assert tls_server["requests"] == []
    else:
        with pytest.raises(ssl.SSLCertVerificationError):
            _send_tls(adapter, tls_server, fault, monkeypatch)
        assert tls_server["requests"] == []
