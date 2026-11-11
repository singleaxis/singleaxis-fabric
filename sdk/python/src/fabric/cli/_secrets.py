# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Generated secrets (spec 058 §7): the pseudonym id key, the local CA and the Node's
certificate, as files in a private directory.

Rules (I7): random material comes from the OS CSPRNG; the directory is 0700 and every file
0600, created exclusively (an existing file is never overwritten), fsynced, and a symlink
is refused. Nothing here returns, prints or logs a secret value: callers get paths,
fingerprints (SHA-256 of a certificate, a keyed id of a key) and expiry only.

Rotation (§7.3) is explicit (``fabric init --rotate NAME``): a new Node certificate is
issued from the existing CA, a new CA comes with a new Node certificate, and a new id key
keeps the old key read-only for the reader."""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import hmac
import ipaddress
import os
import secrets
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ._report import EXIT_USAGE, CliError, Finding

ID_KEY = "id.key"
CA_CERT = "ca.crt"
CA_KEY = "ca.key"
NODE_CERT = "node.crt"
NODE_KEY = "node.key"
RETIRED_DIR = "retired"

#: The names ``fabric init --rotate`` accepts (``all``: every one except the id key, whose
#: rotation changes pseudonyms and is never automatic, §7.3).
ROTATABLE: tuple[str, ...] = ("node-cert", "ca", "id-key")
ID_KEY_BYTES = 32
CA_VALID_DAYS = 730  # §7.2: the local CA is valid 2 years
LEAF_VALID_DAYS = 90  # §7.2: leaf certificates 90 days
RENEW_BEFORE_DAYS = 14  # `fabric up` reissues a Node certificate this close to expiry
#: The Node's name on the Compose network (a SAN, so a containerised agent or the sensor
#: reaching the Node by service name verifies the certificate, §6.4).
NODE_SERVICE = "fabric-node"
NODE_SANS: tuple[str, ...] = ("localhost", NODE_SERVICE, "host.docker.internal")
NODE_IPS: tuple[str, ...] = ("127.0.0.1", "::1")
_FINGERPRINT_LABEL = b"fabric.secret.fingerprint/v1"
_POSIX = os.name == "posix"


def _crypto() -> Any:
    """The ``cryptography`` pieces the generator needs (``FC-005`` when the [cli] extra is
    missing)."""
    try:
        from cryptography import x509  # noqa: PLC0415
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: PLC0415
    except ImportError:
        raise CliError([Finding("FC-005", "cryptography is not installed")], EXIT_USAGE) from None

    return SimpleNamespace(x509=x509, hashes=hashes, serialization=serialization, ec=ec,
                           NameOID=NameOID, ExtendedKeyUsageOID=ExtendedKeyUsageOID)  # fmt: skip


# ---------------------------------------------------------------- where secrets live


def state_home(environ: Mapping[str, str], home: Path | None = None) -> Path:
    """``$XDG_STATE_HOME`` (default ``~/.local/state``); ``%LOCALAPPDATA%`` on Windows."""
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows only
        base = environ.get("LOCALAPPDATA") or str((home or Path.home()) / "AppData" / "Local")
        return Path(base)
    value = (environ.get("XDG_STATE_HOME") or "").strip()
    if value and Path(value).is_absolute():
        return Path(value)
    return (home or Path.home()) / ".local" / "state"


def project_id(project: str, project_dir: Path) -> str:
    """The project name plus a short digest of its directory: two projects with one name
    never share secrets."""
    digest = hashlib.sha256(str(project_dir.resolve()).encode("utf-8")).hexdigest()[:8]
    return f"{project}-{digest}"


def secrets_dir(setting: str, project: str, project_dir: Path, environ: Mapping[str, str],
                home: Path | None = None) -> Path:  # fmt: skip
    """§7.2: ``secrets.dir`` (``auto``: ``<state home>/fabric/<project-id>/secrets``; a
    relative path is relative to the project directory)."""
    if setting == "auto":
        return state_home(environ, home) / "fabric" / project_id(project, project_dir) / "secrets"
    path = Path(setting).expanduser()
    return path if path.is_absolute() else (project_dir / path)


# ---------------------------------------------------------------- private files


def _unsafe_dir(path: Path, why: str) -> CliError:
    return CliError([Finding("FC-012", f"{path}: {why}")])


def _unsafe_file(path: Path, why: str) -> CliError:
    return CliError([Finding("FC-013", f"{path}: {why}")])


def _fsync_dir(directory: Path) -> None:
    if not _POSIX:  # pragma: no cover - Windows has no directory fsync
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` (and its parents) as a private directory, or check an existing one:
    a real directory, owned by this user, closed to group and others."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            return ensure_private_dir(path)
        if _POSIX:
            path.chmod(0o700)  # mkdir's mode is subject to the umask
        _fsync_dir(path.parent)
        return path
    if stat.S_ISLNK(info.st_mode):
        raise _unsafe_dir(path, "is a symlink")
    if not stat.S_ISDIR(info.st_mode):
        raise _unsafe_dir(path, "is not a directory")
    if _POSIX:
        if info.st_uid != os.geteuid():
            raise _unsafe_dir(path, "is owned by another user")
        if info.st_mode & 0o077:
            raise _unsafe_dir(path, "is open to group or others")
    return path


def write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create ``path`` exclusively (``FileExistsError`` when it exists, a symlink
    included), write, fsync the file and its directory."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)  # always created private
    try:
        if _POSIX:
            os.fchmod(fd, mode)  # exact, whatever the umask; a certificate is opened up here
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(path.parent)


def replace(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Atomically put new content at ``path`` (rotation only): a new exclusive file, then
    a rename over the old one."""
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    write_new(temporary, data, mode)
    try:
        os.replace(temporary, path)
    except OSError:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise
    _fsync_dir(path.parent)


def check_secret_file(path: Path, *, public: bool = False) -> bool:
    """Whether ``path`` exists as a safe secret file: a regular file, never a symlink,
    owned by this user and closed to others (a certificate may be world-readable).
    ``FC-013`` when it exists and is not safe."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        raise _unsafe_file(path, "is a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise _unsafe_file(path, "is not a regular file")
    if _POSIX and not public:
        if info.st_uid != os.geteuid():
            raise _unsafe_file(path, "is owned by another user")
        # Group read is allowed only for the Node's key when root shares it with the
        # image's group (the production overlay's root:65532 0440 rule).
        if info.st_mode & 0o037:
            raise _unsafe_file(path, "is open to group or others")
    return True


def _read(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        chunks = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


# ---------------------------------------------------------------- what is generated


@dataclass(frozen=True)
class SecretInfo:
    """One generated secret as the CLI may show it: a name, the files that hold it, what
    this command did (``generated``, ``kept``, ``rotated``, ``renewed``, ``referenced``), a
    fingerprint and an expiry. Never a value."""

    name: str
    files: tuple[str, ...]
    action: str
    fingerprint: str | None = None
    expires: str | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "files": list(self.files), "action": self.action}
        if self.fingerprint:
            out["fingerprint"] = self.fingerprint
        if self.expires:
            out["expires"] = self.expires
        return out


def key_fingerprint(key: bytes) -> str:
    """A keyed id of a symmetric key: it identifies the key without revealing it."""
    return "hmac-sha256:" + hmac.new(key, _FINGERPRINT_LABEL, hashlib.sha256).hexdigest()[:32]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(microsecond=0)


def _certificate(path: Path) -> Any:
    try:
        return _crypto().x509.load_pem_x509_certificate(_read(path))
    except ValueError:
        raise _unsafe_file(path, "is not a PEM certificate") from None


def certificate_info(path: Path) -> tuple[str, dt.datetime]:
    """A certificate's fingerprint (SHA-256 of its DER) and expiry."""
    api = _crypto()
    certificate = _certificate(path)
    der = certificate.public_bytes(api.serialization.Encoding.DER)
    return "sha256:" + hashlib.sha256(der).hexdigest(), certificate.not_valid_after_utc


def _key_pem(api: Any, key: Any) -> bytes:
    pem: bytes = key.private_bytes(api.serialization.Encoding.PEM,
                                   api.serialization.PrivateFormat.PKCS8,
                                   api.serialization.NoEncryption())  # fmt: skip
    return pem


def _new_ca(api: Any, project: str) -> tuple[bytes, bytes]:
    x509 = api.x509
    key = api.ec.generate_private_key(api.ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(api.NameOID.COMMON_NAME, f"fabric local CA ({project})")])
    now = _now()
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .sign(key, api.hashes.SHA256())
    )  # fmt: skip
    return certificate.public_bytes(api.serialization.Encoding.PEM), _key_pem(api, key)


def _new_leaf(api: Any, ca_cert_pem: bytes, ca_key_pem: bytes, names: Sequence[str],
              addresses: Sequence[str]) -> tuple[bytes, bytes]:  # fmt: skip
    x509 = api.x509
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = api.serialization.load_pem_private_key(ca_key_pem, password=None)
    key = api.ec.generate_private_key(api.ec.SECP256R1())
    now = _now()
    not_after = min(now + dt.timedelta(days=LEAF_VALID_DAYS), ca_cert.not_valid_after_utc)
    sans = [x509.DNSName(name) for name in names]
    sans += [x509.IPAddress(ipaddress.ip_address(address)) for address in addresses]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(api.NameOID.COMMON_NAME, NODE_SERVICE)]))
        .issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([api.ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, api.hashes.SHA256())
    )  # fmt: skip
    return certificate.public_bytes(api.serialization.Encoding.PEM), _key_pem(api, key)


def _new_id_key() -> bytes:
    """32 bytes from the OS CSPRNG as 64 hex characters, no trailing newline: the SDK and
    the host emitter read the file's bytes exactly."""
    return secrets.token_bytes(ID_KEY_BYTES).hex().encode("ascii")


def _pair(directory: Path, cert: str, key: str, name: str) -> bool:
    """Whether a certificate pair exists (both halves); ``FC-014`` when only one does."""
    has_cert = check_secret_file(directory / cert, public=True)
    has_key = check_secret_file(directory / key)
    if has_cert != has_key:
        missing = key if has_cert else cert
        raise CliError([Finding("FC-014", f"{name}: {directory / missing} is missing")])
    return has_cert


def _cert_info(directory: Path, name: str, cert: str, key: str, action: str) -> SecretInfo:
    fingerprint, expires = certificate_info(directory / cert)
    return SecretInfo(name, (str(directory / cert), str(directory / key)), action, fingerprint,
                      expires.strftime("%Y-%m-%dT%H:%M:%SZ"))  # fmt: skip


def _id_key_info(path: Path, action: str) -> SecretInfo:
    return SecretInfo("id-key", (str(path),), action, key_fingerprint(_read(path)))


def _issue_leaf(directory: Path, *, exclusive: bool) -> None:
    api = _crypto()
    cert_pem, key_pem = _new_leaf(api, _read(directory / CA_CERT), _read(directory / CA_KEY),
                                  NODE_SANS, NODE_IPS)  # fmt: skip
    if exclusive:
        write_new(directory / NODE_KEY, key_pem)
        write_new(directory / NODE_CERT, cert_pem, 0o644)
    else:
        replace(directory / NODE_KEY, key_pem)
        replace(directory / NODE_CERT, cert_pem, 0o644)


def ensure_local(directory: Path, project: str, *, id_key: bool = True, tls: bool = True
                 ) -> list[SecretInfo]:  # fmt: skip
    """Generate every secret the local profile needs that is missing; never overwrite one
    that exists (§5.3). ``id_key=False`` / ``tls=False``: that secret is referenced from
    elsewhere (an imported setup) and is not generated."""
    ensure_private_dir(directory)
    out: list[SecretInfo] = []
    if id_key:
        path = directory / ID_KEY
        action = "kept"
        if not check_secret_file(path):
            write_new(path, _new_id_key())
            action = "generated"
        out.append(_id_key_info(path, action))
    if tls:
        api = _crypto()
        ca_action = node_action = "kept"
        if not _pair(directory, CA_CERT, CA_KEY, "ca"):
            if _pair(directory, NODE_CERT, NODE_KEY, "node-cert"):
                # A Node certificate without its CA cannot be trusted by anything.
                raise CliError([Finding("FC-014", f"ca: {directory / CA_CERT} is missing")])
            cert_pem, key_pem = _new_ca(api, project)
            write_new(directory / CA_KEY, key_pem)
            write_new(directory / CA_CERT, cert_pem, 0o644)
            ca_action = "generated"
        if not _pair(directory, NODE_CERT, NODE_KEY, "node-cert"):
            _issue_leaf(directory, exclusive=True)
            node_action = "generated"
        out.append(_cert_info(directory, "ca", CA_CERT, CA_KEY, ca_action))
        out.append(_cert_info(directory, "node-cert", NODE_CERT, NODE_KEY, node_action))
    return out


def renew_node_certificate(directory: Path, *, now: dt.datetime | None = None
                           ) -> SecretInfo | None:  # fmt: skip
    """Reissue the Node certificate from the existing CA when it expires within
    :data:`RENEW_BEFORE_DAYS` (agents trust the CA, so nothing else changes). ``FC-027``
    when the CA itself has expired; ``None`` when nothing was due."""
    now = now or _now()
    _, ca_expires = certificate_info(directory / CA_CERT)
    if ca_expires <= now:
        raise CliError([Finding("FC-027", f"expired {ca_expires:%Y-%m-%d}")])
    _, leaf_expires = certificate_info(directory / NODE_CERT)
    if leaf_expires - now > dt.timedelta(days=RENEW_BEFORE_DAYS):
        return None
    _issue_leaf(directory, exclusive=False)
    return _cert_info(directory, "node-cert", NODE_CERT, NODE_KEY, "renewed")


def _retire(directory: Path, name: str, data: bytes, fingerprint: str) -> None:
    """Keep a rotated-out key read-only for the reader (§7.3)."""
    retired = ensure_private_dir(directory / RETIRED_DIR)
    target = retired / f"{name}.{fingerprint.rsplit(':', 1)[-1][:16]}"
    with contextlib.suppress(FileExistsError):
        write_new(target, data, 0o400)


def rotate(directory: Path, project: str, names: Sequence[str]) -> list[SecretInfo]:
    """§7.3 for the local profile's secrets. ``node-cert``: a new certificate from the
    existing CA. ``ca``: a new CA and a new Node certificate. ``id-key``: a new key; the
    old one is kept read-only under ``retired/`` for the reader."""
    ensure_private_dir(directory)
    out: list[SecretInfo] = []
    api = _crypto()
    for name in names:
        if name == "id-key":
            path = directory / ID_KEY
            if check_secret_file(path):
                old = _read(path)
                _retire(directory, ID_KEY, old, key_fingerprint(old))
                replace(path, _new_id_key())
            else:
                write_new(path, _new_id_key())
            out.append(_id_key_info(path, "rotated"))
        elif name == "ca":
            cert_pem, key_pem = _new_ca(api, project)
            for file, data, mode in ((CA_KEY, key_pem, 0o600), (CA_CERT, cert_pem, 0o644)):
                check_secret_file(directory / file, public=file == CA_CERT)
                replace(directory / file, data, mode)
            _issue_leaf(directory, exclusive=False)
            out.append(_cert_info(directory, "ca", CA_CERT, CA_KEY, "rotated"))
            out.append(_cert_info(directory, "node-cert", NODE_CERT, NODE_KEY, "rotated"))
        elif name == "node-cert":
            if not _pair(directory, CA_CERT, CA_KEY, "ca"):
                raise CliError([Finding("FC-014", f"ca: {directory / CA_CERT} is missing")])
            _issue_leaf(directory, exclusive=False)
            out.append(_cert_info(directory, "node-cert", NODE_CERT, NODE_KEY, "rotated"))
    return out


def share_node_key_with_image_group(directory: Path, gid: int) -> None:
    """When ``fabric up`` runs as root the Node keeps its image user: give that user's
    group read access to the Node's key only (root:<gid> 0440, the production overlay's
    rule). A non-root operator's Node runs as the operator instead and needs nothing."""
    path = directory / NODE_KEY
    os.chown(path, 0, gid)
    path.chmod(0o440)


def import_file(directory: Path, name: str, data: bytes, *, public: bool = False) -> Path:
    """``--import-secrets``: store an existing secret as a file, exclusively."""
    ensure_private_dir(directory)
    path = directory / name
    if not check_secret_file(path, public=public):
        write_new(path, data, 0o644 if public else 0o600)
    return path
