# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §7 (I7): generated secrets. Where they live, their modes, exclusive creation,
no overwrite, symlinks refused, what the certificates are, rotation, and that no value is
ever printed."""

from __future__ import annotations

import datetime as dt
import http.server
import os
import ssl
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from fabric._sequence import id_key_from_env
from fabric.cli import _secrets, _up
from fabric.cli._report import CliError

from ._cli_support import mode

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


def _generate(tmp_path: Path) -> Path:
    directory = tmp_path / "state" / "secrets"
    _secrets.ensure_local(directory, "demo")
    return directory


def _finding(caught: pytest.ExceptionInfo[CliError]) -> str:
    (finding,) = caught.value.findings
    return finding.id


# ---------------------------------------------------------------- location (§7.2)


def test_secrets_dir_follows_xdg_state_home_and_is_per_project(tmp_path: Path) -> None:
    one, two = tmp_path / "a" / "agent", tmp_path / "b" / "agent"
    env = {"XDG_STATE_HOME": str(tmp_path / "xdg")}
    first = _secrets.secrets_dir("auto", "agent", one, env)
    second = _secrets.secrets_dir("auto", "agent", two, env)
    assert first.parent.parent == tmp_path / "xdg" / "fabric"
    assert first.name == second.name == "secrets"
    assert first != second, "two projects with one name share a secrets directory"
    assert first.parent.name.startswith("agent-")
    default = _secrets.secrets_dir("auto", "agent", one, {}, home=tmp_path / "home")
    assert default.parts[-5:-2] == (".local", "state", "fabric")
    # A relative XDG_STATE_HOME is invalid per the XDG specification and is ignored.
    assert _secrets.state_home({"XDG_STATE_HOME": "relative"}, tmp_path) == (
        tmp_path / ".local" / "state"
    )


def test_secrets_dir_setting_is_a_path_relative_to_the_project(tmp_path: Path) -> None:
    assert _secrets.secrets_dir("./keys", "p", tmp_path, {}) == tmp_path / "keys"
    assert _secrets.secrets_dir(str(tmp_path / "abs"), "p", tmp_path, {}) == tmp_path / "abs"


# ---------------------------------------------------------------- files (§7.2)


@posix_only
def test_generated_files_have_private_modes_even_under_an_open_umask(tmp_path: Path) -> None:
    old = os.umask(0)
    try:
        directory = _generate(tmp_path)
    finally:
        os.umask(old)
    assert mode(directory) == 0o700
    assert {p.name: mode(p) for p in directory.iterdir()} == {
        "id.key": 0o600, "ca.key": 0o600, "node.key": 0o600, "ca.crt": 0o644, "node.crt": 0o644,
    }  # fmt: skip


def test_existing_secrets_are_never_overwritten(tmp_path: Path) -> None:
    directory = _generate(tmp_path)
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    again = _secrets.ensure_local(directory, "demo")
    assert {info.action for info in again} == {"kept"}
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before


def test_write_new_is_exclusive_and_refuses_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "file"
    _secrets.write_new(target, b"one")
    with pytest.raises(FileExistsError):
        _secrets.write_new(target, b"two")
    assert target.read_bytes() == b"one"
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(FileExistsError):
        _secrets.write_new(link, b"data")
    assert not (tmp_path / "elsewhere").exists(), "a write followed a symlink"


@posix_only
def test_a_symlinked_or_open_secrets_directory_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(CliError) as caught:
        _secrets.ensure_local(link, "demo")
    assert _finding(caught) == "FC-012"
    assert list(real.iterdir()) == []
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o750)
    shared.chmod(0o750)
    with pytest.raises(CliError) as caught:
        _secrets.ensure_local(shared, "demo")
    assert _finding(caught) == "FC-012"
    file = tmp_path / "file"
    file.write_text("x")
    with pytest.raises(CliError) as caught:
        _secrets.ensure_local(file, "demo")
    assert _finding(caught) == "FC-012"


@posix_only
def test_a_symlinked_or_world_readable_secret_file_is_refused(tmp_path: Path) -> None:
    directory = _generate(tmp_path)
    (directory / "id.key").chmod(0o644)
    with pytest.raises(CliError) as caught:
        _secrets.ensure_local(directory, "demo")
    assert _finding(caught) == "FC-013"
    (directory / "id.key").unlink()
    (directory / "id.key").symlink_to(tmp_path / "attacker")
    with pytest.raises(CliError) as caught:
        _secrets.ensure_local(directory, "demo")
    assert _finding(caught) == "FC-013"
    assert not (tmp_path / "attacker").exists()


def test_half_a_certificate_pair_is_reported_not_silently_replaced(tmp_path: Path) -> None:
    directory = _generate(tmp_path)
    crt = (directory / "node.crt").read_bytes()
    (directory / "node.key").unlink()
    with pytest.raises(CliError) as caught:
        _secrets.ensure_local(directory, "demo")
    assert _finding(caught) == "FC-014"
    assert (directory / "node.crt").read_bytes() == crt
    (directory / "node.crt").unlink()
    (directory / "ca.key").unlink()
    with pytest.raises(CliError) as caught:
        _secrets.ensure_local(directory, "demo")
    assert _finding(caught) == "FC-014"


# ---------------------------------------------------------------- what is generated


def test_id_key_is_32_random_bytes_the_sdk_reads_from_the_file(tmp_path: Path) -> None:
    directory = _generate(tmp_path)
    raw = (directory / "id.key").read_bytes()
    assert len(raw) == 64 and bytes.fromhex(raw.decode()) and not raw.endswith(b"\n")
    assert id_key_from_env({"FABRIC_WIRE_ID_KEY_FILE": str(directory / "id.key")}) == raw
    other = _generate(tmp_path / "other")
    assert (other / "id.key").read_bytes() != raw


def test_ca_and_node_certificate_follow_section_7_2(tmp_path: Path) -> None:
    directory = _generate(tmp_path)
    ca = x509.load_pem_x509_certificate((directory / "ca.crt").read_bytes())
    leaf = x509.load_pem_x509_certificate((directory / "node.crt").read_bytes())
    for certificate in (ca, leaf):
        key = certificate.public_key()
        assert isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"
    leaf.verify_directly_issued_by(ca)
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    now = dt.datetime.now(dt.UTC)
    assert dt.timedelta(days=729) < ca.not_valid_after_utc - now <= dt.timedelta(days=730)
    assert dt.timedelta(days=89) < leaf.not_valid_after_utc - now <= dt.timedelta(days=90)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(san.get_values_for_type(x509.DNSName)) >= {"localhost", "fabric-node"}
    assert "127.0.0.1" in {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]


@pytest.fixture()
def tls_server(tmp_path: Path) -> Iterator[tuple[int, Path]]:
    """A loopback HTTPS server with the generated Node certificate."""
    directory = _generate(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / "node.crt", directory / "node.key")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], directory
    finally:
        server.shutdown()
        server.server_close()


def test_node_certificate_serves_tls_that_the_generated_ca_verifies(
    tls_server: tuple[int, Path], tmp_path: Path
) -> None:
    """The TLS listener with the generated CA (WP8-3): `fabric up`'s health probe verifies
    the Node's certificate against ca.crt, and refuses another CA."""
    port, directory = tls_server
    assert _up.node_answers(port, directory / "ca.crt") is True
    other = _generate(tmp_path / "other")
    assert _up.node_answers(port, other / "ca.crt") is False
    assert _up.node_answers(1, directory / "ca.crt", timeout=0.2) is False


# ---------------------------------------------------------------- rotation (§7.3)


def _bytes(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}


def test_rotating_the_node_certificate_keeps_the_ca(tmp_path: Path) -> None:
    directory = _generate(tmp_path)
    before = _bytes(directory)
    (info,) = _secrets.rotate(directory, "demo", ["node-cert"])
    after = _bytes(directory)
    assert info.action == "rotated" and info.name == "node-cert"
    assert after["ca.crt"] == before["ca.crt"] and after["ca.key"] == before["ca.key"]
    assert after["node.crt"] != before["node.crt"] and after["node.key"] != before["node.key"]
    assert after["id.key"] == before["id.key"]
    x509.load_pem_x509_certificate(after["node.crt"]).verify_directly_issued_by(
        x509.load_pem_x509_certificate(after["ca.crt"])
    )
    if os.name == "posix":
        assert mode(directory / "node.key") == 0o600


def test_rotating_the_ca_issues_a_new_node_certificate_under_it(tmp_path: Path) -> None:
    directory = _generate(tmp_path)
    before = _bytes(directory)
    names = [info.name for info in _secrets.rotate(directory, "demo", ["ca"])]
    after = _bytes(directory)
    assert names == ["ca", "node-cert"]
    assert after["ca.crt"] != before["ca.crt"] and after["node.crt"] != before["node.crt"]
    x509.load_pem_x509_certificate(after["node.crt"]).verify_directly_issued_by(
        x509.load_pem_x509_certificate(after["ca.crt"])
    )


def test_rotating_the_id_key_keeps_the_old_key_read_only_for_the_reader(tmp_path: Path) -> None:
    directory = _generate(tmp_path)
    old = (directory / "id.key").read_bytes()
    (info,) = _secrets.rotate(directory, "demo", ["id-key"])
    assert (directory / "id.key").read_bytes() != old
    assert info.fingerprint != _secrets.key_fingerprint(old)
    (retired,) = list((directory / "retired").iterdir())
    assert retired.read_bytes() == old
    if os.name == "posix":
        assert mode(retired) == 0o400 and mode(directory / "retired") == 0o700


def test_a_node_certificate_close_to_expiry_is_reissued_from_the_same_ca(tmp_path: Path) -> None:
    directory = _generate(tmp_path)
    before = _bytes(directory)
    now = dt.datetime.now(dt.UTC)
    assert _secrets.renew_node_certificate(directory, now=now + dt.timedelta(days=10)) is None
    renewed = _secrets.renew_node_certificate(directory, now=now + dt.timedelta(days=80))
    assert renewed is not None and renewed.action == "renewed"
    after = _bytes(directory)
    assert after["node.crt"] != before["node.crt"] and after["ca.crt"] == before["ca.crt"]
    with pytest.raises(CliError) as caught:
        _secrets.renew_node_certificate(directory, now=now + dt.timedelta(days=800))
    assert _finding(caught) == "FC-027"


# ---------------------------------------------------------------- never a value


def test_secret_info_carries_names_fingerprints_and_expiry_only(tmp_path: Path) -> None:
    directory = tmp_path / "secrets"
    infos = _secrets.ensure_local(directory, "demo")
    rendered = repr(infos) + repr([info.to_json() for info in infos])
    for path in directory.iterdir():
        if path.suffix != ".crt":
            for line in path.read_bytes().splitlines():
                if line and not line.startswith(b"-----"):
                    assert line.decode() not in rendered
    by_name = {info.name: info.to_json() for info in infos}
    assert set(by_name) == {"id-key", "ca", "node-cert"}
    assert by_name["id-key"]["fingerprint"].startswith("hmac-sha256:")
    assert by_name["ca"]["fingerprint"].startswith("sha256:") and by_name["ca"]["expires"]
    assert set(by_name["node-cert"]) == {"name", "files", "action", "fingerprint", "expires"}


def test_fingerprint_of_a_key_does_not_reveal_it() -> None:
    key = b"k" * 64
    fingerprint = _secrets.key_fingerprint(key)
    assert fingerprint == _secrets.key_fingerprint(key)
    assert fingerprint != _secrets.key_fingerprint(b"j" * 64)
    assert key.decode() not in fingerprint and key.hex() not in fingerprint


def test_without_the_cli_extra_the_message_names_the_install_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in [m for m in sys.modules if m == "cryptography" or m.startswith("cryptography.")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "cryptography", None)
    with pytest.raises(CliError) as caught:
        _secrets.ensure_local(tmp_path / "secrets", "demo")
    assert _finding(caught) == "FC-005"


@posix_only
def test_root_shares_only_the_node_key_with_the_image_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _generate(tmp_path)
    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: chowned.append((Path(p).name, u, g)))
    _secrets.share_node_key_with_image_group(directory, 65532)
    assert chowned == [("node.key", 0, 65532)]
    assert mode(directory / "node.key") == 0o440
    assert mode(directory / "ca.key") == 0o600 and mode(directory / "id.key") == 0o600
    # Group read on the Node key is the one mode beyond 0600 the checks accept.
    assert _secrets.check_secret_file(directory / "node.key") is True


def test_import_file_stores_exclusively_and_never_replaces(tmp_path: Path) -> None:
    directory = tmp_path / "secrets"
    path = _secrets.import_file(directory, "id.key", b"first-imported-key")
    assert path.read_bytes() == b"first-imported-key"
    _secrets.import_file(directory, "id.key", b"second")
    assert path.read_bytes() == b"first-imported-key"
