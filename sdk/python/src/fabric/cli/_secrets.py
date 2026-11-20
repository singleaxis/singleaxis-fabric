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

import base64
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

#: Production (spec 058 §7.1): the agent's spool key, the Node's content key, the sensor's
#: state key, and per ingress source a bearer token (and, for the SDK's senders, the same
#: token as the OTLP headers file the SDK reads) and a client certificate.
SPOOL_KEY = "spool.key"
CONTENT_KEY = "content.key"
SENSOR_STATE_KEY = "ebpf-state.key"
#: The sources a production project binds on the Node, each its own ingress group: the
#: agent, the host sensor, and the canary `fabric verify` sends (never an agent's).
SOURCES: tuple[str, ...] = ("agent", "ebpf", "canary")
#: The sources that send through the SDK, which reads its token from a headers file.
HEADER_SOURCES: tuple[str, ...] = ("agent", "canary")
#: Trial destination (§9.2): the TLS OTLP receiver and S3-compatible store `fabric up`
#: provisions, their certificates, the store's three identities and its SSE key, and the
#: token the Node presents to the receiver.
TRIAL_OTLP_SERVICE = "fabric-trial-otlp"
TRIAL_S3_SERVICE = "fabric-trial-s3"
TRIAL_EXPORT_TOKEN = "trial-export.token"  # noqa: S105 - a file name
TRIAL_S3_KEK = "trial-s3-sse.kek"
TRIAL_S3_IDENTITIES: tuple[str, ...] = ("root", "node", "reader")


def token_file(source: str) -> str:
    return f"{source}.token"


def headers_file(source: str) -> str:
    return f"{source}.headers"


def client_pair(source: str) -> tuple[str, str]:
    return f"{source}-client.crt", f"{source}-client.key"


def trial_credentials(identity: str) -> str:
    return f"trial-s3-{identity}.credentials"


#: The files the Node's container user reads (shared with its group when root runs it).
NODE_READ = frozenset({NODE_KEY, CONTENT_KEY, *(token_file(s) for s in SOURCES),
                       trial_credentials("node")})  # fmt: skip
#: The names ``fabric init --rotate`` accepts (``all``: every one except the id key, whose
#: rotation changes pseudonyms and is never automatic, §7.3). ``tokens`` and
#: ``client-certs`` exist in the production profile only.
ROTATABLE: tuple[str, ...] = ("node-cert", "ca", "id-key", "tokens", "client-certs")
PRODUCTION_ROTATABLE = frozenset({"tokens", "client-certs"})
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
        # Group read is allowed only for the files the Node reads, which root shares
        # with the image's group (the production overlay's root:65532 0440 rule).
        if info.st_mode & (0o037 if path.name in NODE_READ else 0o077):
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
              addresses: Sequence[str], *, common_name: str = NODE_SERVICE, client: bool = False,
              valid_days: int = LEAF_VALID_DAYS) -> tuple[bytes, bytes]:  # fmt: skip
    """A leaf certificate from the CA: a server certificate for ``names``/``addresses``, or
    (``client``) a client certificate. Never valid beyond the CA."""
    x509 = api.x509
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = api.serialization.load_pem_private_key(ca_key_pem, password=None)
    key = api.ec.generate_private_key(api.ec.SECP256R1())
    now = _now()
    not_after = min(now + dt.timedelta(days=valid_days), ca_cert.not_valid_after_utc)
    sans = [x509.DNSName(name) for name in names]
    sans += [x509.IPAddress(ipaddress.ip_address(address)) for address in addresses]
    usage = api.ExtendedKeyUsageOID.CLIENT_AUTH if client else api.ExtendedKeyUsageOID.SERVER_AUTH
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(api.NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
    )  # fmt: skip
    if sans:  # a client certificate names no host
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    certificate = builder.sign(ca_key, api.hashes.SHA256())
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


# ---------------------------------------------------------------- production (§7.1)


TOKEN_BYTES = 32  # 64 hex characters: within the Node's 32-4096 printable-byte rule
_HEADERS_PREFIX = b"Authorization=Bearer%20"


def _new_token() -> bytes:
    """A bearer token: 32 CSPRNG bytes as hex, no trailing newline (the Node's
    bearertokenauth reads the file's bytes exactly)."""
    return secrets.token_bytes(TOKEN_BYTES).hex().encode("ascii")


def _new_key_b64() -> bytes:
    """A 32-byte key as base64 text, no newline (the SDK's and the Node's key files)."""
    return base64.b64encode(secrets.token_bytes(32))


def headers_for(token: bytes) -> bytes:
    """The OTLP headers file the SDK reads (``FABRIC_OTLP_HEADERS_FILE``) for a token."""
    return _HEADERS_PREFIX + token


def token_from_headers(raw: bytes) -> bytes | None:
    body = raw[:-1] if raw.endswith(b"\n") else raw
    if not body.startswith(_HEADERS_PREFIX):
        return None
    token = body[len(_HEADERS_PREFIX) :]
    return token if token and token.isalnum() else None


def _key_info(directory: Path, name: str, label: str, action: str) -> SecretInfo:
    return SecretInfo(label, (str(directory / name),), action,
                      key_fingerprint(_read(directory / name)))  # fmt: skip


def _ensure_key(directory: Path, name: str, label: str, make: Any) -> SecretInfo:
    path = directory / name
    action = "kept"
    if not check_secret_file(path):
        write_new(path, make())
        action = "generated"
    return _key_info(directory, name, label, action)


def _ensure_token(directory: Path, source: str, *, check_pair: bool = True) -> SecretInfo:
    """A source's token and (for an SDK sender) its headers file, generated together. One
    half missing is made from the other; two halves that disagree are ``FC-169``, unless
    ``check_pair`` is off because ``--rotate tokens`` replaces both next (FC-169's fix)."""
    token_path = directory / token_file(source)
    has_token = check_secret_file(token_path)
    header_path = directory / headers_file(source) if source in HEADER_SOURCES else None
    has_headers = header_path is not None and check_secret_file(header_path)
    action = "kept"
    token = _read(token_path) if has_token else None
    if header_path is not None and has_headers:
        from_headers = token_from_headers(_read(header_path))
        if from_headers is None or (token is not None and token != from_headers):
            if check_pair:
                raise CliError([Finding("FC-169", f"{header_path} is not the headers file of "
                                                  f"{token_path}")])  # fmt: skip
        else:
            token = from_headers
    if token is None:
        token = _new_token()
        action = "generated"
    if not has_token:
        write_new(token_path, token)
    if header_path is not None and not has_headers:
        write_new(header_path, headers_for(token))
    files = (str(token_path),) + ((str(header_path),) if header_path is not None else ())
    return SecretInfo(f"{source}-token", files, action, key_fingerprint(token))


def _ensure_leaf(directory: Path, pair: tuple[str, str], label: str, names: Sequence[str],
                 addresses: Sequence[str], *, common_name: str, client: bool,
                 rotate: bool = False) -> SecretInfo:  # fmt: skip
    cert, key = pair
    action = "kept"
    if rotate or not _pair(directory, cert, key, label):
        api = _crypto()
        cert_pem, key_pem = _new_leaf(api, _read(directory / CA_CERT), _read(directory / CA_KEY),
                                      names, addresses, common_name=common_name,
                                      client=client)  # fmt: skip
        if rotate and (directory / cert).exists():
            replace(directory / key, key_pem)
            replace(directory / cert, cert_pem, 0o644)
            action = "rotated"
        else:
            write_new(directory / key, key_pem)
            write_new(directory / cert, cert_pem, 0o644)
            action = "generated"
    return _cert_info(directory, label, cert, key, action)


def _client_certs(directory: Path, labels: Mapping[str, str], *, rotate: bool = False
                  ) -> list[SecretInfo]:  # fmt: skip
    """One client certificate per source, its common name the source's clear label."""
    return [_ensure_leaf(directory, client_pair(source), f"{source}-client-cert", (), (),
                         common_name=labels[source], client=True, rotate=rotate)
            for source in SOURCES]  # fmt: skip


def _trial_certs(directory: Path, *, rotate: bool = False) -> list[SecretInfo]:
    return [
        _ensure_leaf(directory, (f"{name}.crt", f"{name}.key"), f"{name}-cert",
                     (service, "localhost"), NODE_IPS, common_name=service, client=False,
                     rotate=rotate)
        for name, service in (("trial-otlp", TRIAL_OTLP_SERVICE), ("trial-s3", TRIAL_S3_SERVICE))
    ]  # fmt: skip


def _new_credentials(identity: str) -> bytes:
    """An AWS shared-credentials file for one identity of the trial store."""
    access = f"fabric-{identity}-{secrets.token_hex(4)}"
    secret = secrets.token_hex(24)
    return (f"[default]\naws_access_key_id = {access}\n"
            f"aws_secret_access_key = {secret}\n").encode("ascii")  # fmt: skip


def ensure_production(directory: Path, labels: Mapping[str, str], *, trial: bool,
                      rotating_tokens: bool = False) -> list[SecretInfo]:  # fmt: skip
    """Generate every production secret that is missing (§7.1); never overwrite one.
    ``labels`` maps each of :data:`SOURCES` to its clear source label (the client
    certificate's common name). The CA must exist (:func:`ensure_local` first). With
    ``rotating_tokens`` a token and headers pair that disagree is left for the rotation
    that follows to replace, instead of refused."""
    ensure_private_dir(directory)
    if not _pair(directory, CA_CERT, CA_KEY, "ca"):
        raise CliError([Finding("FC-014", f"ca: {directory / CA_CERT} is missing")])
    out = [
        _ensure_key(directory, SPOOL_KEY, "spool-key", _new_key_b64),
        _ensure_key(directory, CONTENT_KEY, "content-key", _new_key_b64),
        _ensure_key(directory, SENSOR_STATE_KEY, "ebpf-state-key", _new_key_b64),
        *(_ensure_token(directory, source, check_pair=not rotating_tokens) for source in SOURCES),
        *_client_certs(directory, labels),
    ]
    if trial:
        out += _trial_certs(directory)
        out += [_ensure_key(directory, trial_credentials(identity), f"trial-s3-{identity}",
                            lambda identity=identity: _new_credentials(identity))
                for identity in TRIAL_S3_IDENTITIES]  # fmt: skip
        out.append(_ensure_key(directory, TRIAL_S3_KEK, "trial-s3-sse-kek", _new_token))
        out.append(_ensure_key(directory, TRIAL_EXPORT_TOKEN, "trial-export-token", _new_token))
    return out


def rotate_production(directory: Path, names: Sequence[str], labels: Mapping[str, str], *,
                      trial: bool) -> list[SecretInfo]:  # fmt: skip
    """§7.3 for the production secrets. ``tokens``: a new token (and headers file) per
    source, the old one kept read-only under ``retired/``. ``client-certs``: new client
    certificates from the CA. ``ca`` (after :func:`rotate`): the client and trial
    certificates the old CA signed are reissued from the new one."""
    ensure_private_dir(directory)
    out: list[SecretInfo] = []
    if "tokens" in names:
        for source in SOURCES:
            path = directory / token_file(source)
            if check_secret_file(path):
                old = _read(path)
                _retire(directory, token_file(source), old, key_fingerprint(old))
            token = _new_token()
            replace(path, token)
            files = [str(path)]
            if source in HEADER_SOURCES:
                replace(directory / headers_file(source), headers_for(token))
                files.append(str(directory / headers_file(source)))
            out.append(SecretInfo(f"{source}-token", tuple(files), "rotated",
                                  key_fingerprint(token)))  # fmt: skip
    if "client-certs" in names or "ca" in names:
        out += _client_certs(directory, labels, rotate=True)
    if "ca" in names and trial:
        out += _trial_certs(directory, rotate=True)
    return out
