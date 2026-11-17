# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric snapshot`` (spec 057 §4.10.2, WP7-17; spec 058 OQ-3): the operator's snapshot
of the agent's permission files.

The customer lists its permission and policy files in the capture policy's
``security_context.watched_paths`` with class ``permission_config``. A host sensor records
each open the agent makes of one (label, class and a keyed ``pth-`` id, never the path).
This command, run by the operator **outside the agent process**, records what those files
say: one ``declared`` grant snapshot per listed entry, with source boundary
``operator_snapshot`` and the same ``pth-`` id, so the reader shows each watched open with
the snapshot of that file and the time between the two (link ``path_ref``).

What is recorded:

- on telemetry, ids only: the keyed ``grt-`` id of the snapshot, the ``pth-`` id of the
  entry, the previous ``grt-`` id when the file changed. Never the path, the label's file
  or any content;
- as ``run.permissions`` content, only when the capture policy retains that role (it is
  omitted under the default production profile): the grant document, whose
  ``x-fabric-rule-file`` member holds each file's digest, size and contents verbatim.
  The contents are never parsed, interpreted or applied (spec 057 B6).

The command reads only the listed files, once, when the operator runs it. It installs
nothing in the agent, watches nothing and schedules nothing; the agent process never opens
a file on Fabric's behalf. The records go through the project's own capture configuration
in a worker process (``python -m fabric.cli._snapshot``), as the canary of ``fabric
verify`` does, so the Node, the destination and the reader are the user's real path.
``.fabric/state/snapshots.json`` keeps the last ``grt-`` id per ``pth-`` id (keyed ids
only), which is how a changed file is told from an unchanged one.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import errno
import hashlib
import json
import os
import re
import secrets as _random
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from . import _config, _project, _run, _runstate
from ._report import EXIT_FINDINGS, CliError, Finding, Report

SNAPSHOT_CLASS = "permission_config"
EXTENSION = "x-fabric-rule-file"
STATE_SCHEMA = "fabric.cli-snapshots/v1"
#: The bytes of one file a snapshot keeps as content; a larger file is recorded by digest
#: and size. The whole document must also fit the ``run.permissions`` role's body limit as
#: the SDK's bounded walker counts it (every character as up to 6 bytes, spec 051 §4.2):
#: the contents of the largest files are left out first until it does (:func:`fit`).
FILE_LIMIT = 128 * 1024
#: A file is hashed in full up to this size; beyond it the entry is refused.
HASH_LIMIT = 64 * 1024 * 1024
MAX_FILES = 256  # the files of one directory entry
MAX_DEPTH = 8
MAX_LIST_BYTES = 4 * 1024 * 1024
WORKER_TIMEOUT_S = 90.0
CLOSE_TIMEOUT_S = 20.0
_PATH = re.compile(r"/[ -~]{0,4095}")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_CLASSES = frozenset({"permission_config", "hook_config", "extension_dir", "credential_file",
                      "other"})  # fmt: skip
_ENTRY_KEYS = frozenset({"path", "match", "label", "class"})
_LIST_FORMS = (
    "a JSON list of objects with path, match, label and class, or a deployment policy in JSON"
)


# ---------------------------------------------------------------- the list


def _invalid(detail: str) -> CliError:
    return CliError([Finding("FC-101", detail)])


def _entry(index: int, entry: object) -> dict[str, str]:
    where = f"watched_paths[{index}]"
    if not isinstance(entry, Mapping):
        raise _invalid(f"{where} must be an object with path, match, label and class")
    unknown = sorted(str(k) for k in entry.keys() - _ENTRY_KEYS)
    if unknown:
        raise _invalid(f"{where} has an unknown field {unknown[0]!r}; remove it")
    for name in sorted(_ENTRY_KEYS):
        if not isinstance(entry.get(name), str):
            raise _invalid(f"{where}.{name} is missing or is not text")
    if _PATH.fullmatch(entry["path"]) is None:
        raise _invalid(f"{where}.path must be an absolute path of printable ASCII "
                       "(at most 4096 characters)")  # fmt: skip
    if entry["match"] not in ("exact", "prefix"):
        raise _invalid(f"{where}.match must be exact or prefix")
    if _LABEL.fullmatch(entry["label"]) is None:
        raise _invalid(f"{where}.label must start with a letter or digit and hold only "
                       "letters, digits and . _ : / - (at most 128 characters)")  # fmt: skip
    if entry["class"] not in _CLASSES:
        raise _invalid(f"{where}.class must be one of {', '.join(sorted(_CLASSES))}")
    return {name: entry[name] for name in ("path", "match", "label", "class")}


def load_watched(path: Path) -> list[dict[str, str]]:
    """The ``permission_config`` entries of a watched paths file: the list itself, or a
    deployment policy whose ``security_context`` holds it (the two forms the host sensor
    reads). Every entry is checked as the policy schema does; an error names the entry by
    index and the rule, and how to fix it."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_LIST_BYTES + 1)
    except OSError as exc:
        raise _invalid(f"{path}: {type(exc).__name__}; check the path and that this user "
                       "can read it") from None  # fmt: skip
    if len(raw) > MAX_LIST_BYTES:
        raise _invalid(f"{path} is larger than {MAX_LIST_BYTES // (1024 * 1024)} MiB")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise _invalid(f"{path} is not JSON; give {_LIST_FORMS}") from None
    if isinstance(document, Mapping):
        section = document.get("security_context")
        document = section.get("watched_paths", []) if isinstance(section, Mapping) else []
    if not isinstance(document, list):
        raise _invalid(f"{path}: watched_paths must be a list; give {_LIST_FORMS}")
    entries = [_entry(index, entry) for index, entry in enumerate(document)]
    return [entry for entry in entries if entry["class"] == SNAPSHOT_CLASS]


# ---------------------------------------------------------------- reading the files


class _UnreadableError(Exception):
    """An entry that cannot be snapshotted: a fixed reason, never the path."""


def _reason(exc: OSError) -> str:
    name = errno.errorcode.get(exc.errno or 0)
    return f"{type(exc).__name__}" + (f" ({name})" if name else "")


def _read_file(path: str, *, follow: bool = True) -> tuple[str, int, bytes | None]:
    """One regular file as ``(sha256 hex, size, bytes or None)``; the bytes only up to
    :data:`FILE_LIMIT`. Never follows a FIFO or device into a blocking read, nor, with
    ``follow`` false, a symbolic link."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    if not follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _UnreadableError(_reason(exc)) from None
    try:
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            raise _UnreadableError("it is a directory; list it with match: prefix")
        if not stat.S_ISREG(info.st_mode):
            raise _UnreadableError("it is not a regular file")
        digest = hashlib.sha256()
        kept: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            size += len(chunk)
            if size > HASH_LIMIT:
                raise _UnreadableError(f"it is larger than {HASH_LIMIT // (1024 * 1024)} MiB")
            digest.update(chunk)
            if size <= FILE_LIMIT:
                kept.append(chunk)
        return digest.hexdigest(), size, b"".join(kept) if size <= FILE_LIMIT else None
    except OSError as exc:
        raise _UnreadableError(_reason(exc)) from None
    finally:
        os.close(fd)


def _directory_files(root: str, errors: list[str]) -> tuple[list[str], list[str]]:
    """The regular files under a ``prefix`` entry, sorted, never through a symbolic link;
    and what was left out (``unreadable``, ``file_limit``, ``depth_limit``). The reason of
    each folder or file that could not be read is added to ``errors``."""
    try:
        if not stat.S_ISDIR(os.stat(root).st_mode):
            raise _UnreadableError("it is not a directory; list a single file with match: exact")
    except OSError as exc:
        raise _UnreadableError(_reason(exc)) from None
    found: list[str] = []
    incomplete: set[str] = set()
    base = root.rstrip("/") or "/"

    def failed(exc: OSError) -> None:
        incomplete.add("unreadable")
        errors.append(_reason(exc))

    for current, directories, names in os.walk(base, onerror=failed, followlinks=False):
        directories.sort()
        depth = 0 if current == base else current[len(base) :].strip("/").count("/") + 1
        if depth >= MAX_DEPTH and directories:
            incomplete.add("depth_limit")
            directories[:] = []
        for name in sorted(names):
            full = os.path.join(current, name)
            try:
                if not stat.S_ISREG(os.lstat(full).st_mode):
                    continue
            except OSError as exc:
                failed(exc)
                continue
            if len(found) >= MAX_FILES:
                incomplete.add("file_limit")
                return found, sorted(incomplete)
            found.append(full)
    return found, sorted(incomplete)


def read_entry(entry: Mapping[str, str], path_id: Callable[[str], str]) -> dict[str, Any]:
    """The ``x-fabric-rule-file`` member of one entry's grant document: per file its keyed
    ``pth-`` id (never its name), SHA-256, size and, within the limits, its contents
    verbatim (UTF-8 text, else base64). Raises :class:`_UnreadableError` when nothing of the
    entry can be read."""
    incomplete: set[str] = set()
    errors: list[str] = []
    if entry["match"] == "exact":
        paths = [entry["path"]]
    else:
        paths, left_out = _directory_files(entry["path"], errors)
        incomplete.update(left_out)
    files: list[dict[str, Any]] = []
    for path in paths:
        try:
            # A file under a prefix entry is never opened through a symbolic link.
            digest, size, data = _read_file(path, follow=entry["match"] == "exact")
        except _UnreadableError as exc:
            if entry["match"] == "exact":
                raise
            incomplete.add("unreadable")
            errors.append(str(exc))
            continue
        row: dict[str, Any] = {"path_ref": path_id(path), "sha256": digest, "bytes": size}
        if data is None:
            row["content_omitted"] = "size_limit"
            incomplete.add("size_limit")
        else:
            try:
                row["content"] = data.decode("utf-8")
                row["encoding"] = "utf-8"
            except UnicodeDecodeError:
                row["content"] = base64.b64encode(data).decode("ascii")
                row["encoding"] = "base64"
        files.append(row)
    if not files and errors:
        # Nothing under the folder could be read: an empty snapshot would say the folder
        # holds no rule file, which was not observed.
        raise _UnreadableError(f"none of its files could be read ({errors[0]})")
    out: dict[str, Any] = {"match": entry["match"], "files": files}
    if incomplete:
        out["incomplete"] = sorted(incomplete)
    return out


def fit(document: dict[str, Any], cap: int) -> dict[str, Any]:
    """``document`` with the contents of its largest files left out (``size_limit``) until
    the SDK's bounded walker accepts it within ``cap``, the ``run.permissions`` role's body
    limit: a document over it would be recorded with no body at all (``payload_too_large``)
    while the snapshot reported its contents kept. Deterministic, so an unchanged file set
    gives the same grant id."""
    from fabric.records._walker import walk  # noqa: PLC0415 - the worker only

    member = document[EXTENSION]
    held = sorted((row for row in member["files"] if "content" in row),
                  key=lambda row: (-len(row["content"]), row["path_ref"]))  # fmt: skip
    for row in held:
        if walk(document, cap).outcome == "ok":
            break
        del row["content"], row["encoding"]
        row["content_omitted"] = "size_limit"
        member["incomplete"] = sorted({*member.get("incomplete", ()), "size_limit"})
    return document


# ---------------------------------------------------------------- the worker process


def _status(path: str) -> dict[str, Any] | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def record(payload: Mapping[str, Any], status_file: str) -> dict[str, Any]:
    """The worker: install capture from this process's environment (the project's compiled
    environment), read each entry and emit its grant snapshot inside one labelled run,
    then deliver. Returns ids and counts only; never a path or content."""
    for name in ("FABRIC_WIRE_AUTOLOAD", "FABRIC_RUN_ID", "FABRIC_RUN_RESUME_TOKEN"):
        os.environ.pop(name, None)
    os.environ["FABRIC_WIRE_STATUS_FILE"] = status_file
    out: dict[str, Any] = {"installed": False, "delivered": False, "entries": []}
    from fabric import _rec_grant, _records_api, wire  # noqa: PLC0415 - the worker only
    from fabric._sequence import pseudonym_v2  # noqa: PLC0415

    handle = wire.install_from_env()
    if handle is None or not handle.capturing:
        out["status"] = _status(status_file)
        return out
    out["installed"] = True
    previous: Mapping[str, Any] = payload.get("previous") or {}
    try:
        with wire.run(str(payload["label"])):
            records = _records_api.current_records()
            key = getattr(records, "_key", None)
            if records is None or key is None:
                out["error"] = "no_id_key" if records is not None else "records_inactive"
            else:
                mode = str(records.mode_of("run.permissions"))
                out["contents"] = contents_of(mode)
                out["contents_mode"] = mode
                for index, entry in enumerate(payload["entries"]):
                    try:
                        row = _record_entry(index, entry, records, key, previous, _rec_grant,
                                            pseudonym_v2)  # fmt: skip
                    except Exception as exc:  # one entry's fault never hides the others
                        row = {"index": index, "label": entry.get("label"), "recorded": False,
                               "error": f"the snapshot failed ({type(exc).__name__})"}  # fmt: skip
                    out["entries"].append(row)
    except Exception as exc:  # reported, never raised: the answer names the class only
        out["error"] = type(exc).__name__
    out["delivered"] = bool(handle.close(CLOSE_TIMEOUT_S))
    out["status"] = _status(status_file)
    return out


#: Why files under a ``prefix`` entry were left out of its snapshot (``FC-110``).
_LEFT_OUT = {
    "unreadable": "a file or folder under it could not be read",
    "file_limit": f"it holds more than {MAX_FILES} files; the first {MAX_FILES} were read",
    "depth_limit": f"folders more than {MAX_DEPTH} levels deep were not read",
}

#: The ``run.permissions`` modes that keep the bytes as given, and those that keep none
#: (``metadata_only`` stores a descriptor without bytes); any other mode keeps them masked.
_KEEPING = frozenset({"retain_original", "original_plus_masked"})
_DROPPING = frozenset({"omit", "metadata_only"})


def contents_of(mode: str) -> str:
    """What becomes of the files' contents under the ``run.permissions`` mode ``mode``."""
    if mode in _KEEPING:
        return "kept"
    return "not_kept" if mode in _DROPPING else "masked"


def _record_entry(
    index: int,
    entry: Mapping[str, str],
    records: Any,
    key: bytes,
    previous: Mapping[str, Any],
    grants: Any,
    pseudonym: Callable[[str, str, bytes], str | None],
) -> dict[str, Any]:
    # The id of the entry's configured path, exactly as written: the id a host sensor
    # puts on every open under the entry (spec 057 rev 3.10 note 5).
    path_ref = str(pseudonym("pth", entry["path"], key))
    row: dict[str, Any] = {"index": index, "label": entry["label"], "path_ref": path_ref,
                           "recorded": False}  # fmt: skip
    try:
        member = read_entry(entry, lambda path: str(pseudonym("pth", path, key)))
    except _UnreadableError as exc:
        row["error"] = str(exc)
        return row
    document = grants.check_document(
        {
            "schema_version": grants.SCHEMA_VERSION,
            "basis": "declared",
            "source": {"boundary": "operator_snapshot", "name": entry["label"],
                       "path_ref": path_ref},
            EXTENSION: member,
        }
    )  # fmt: skip
    if document is None or EXTENSION not in document:
        row["error"] = "the snapshot document was refused"
        return row
    from fabric._records_api import role_cap  # noqa: PLC0415 - the worker only

    member = fit(document, role_cap("run.permissions"))[EXTENSION]
    grant_id = grants.grant_id(grants.grant_digest(document), key)
    last = previous.get(path_ref)
    changed = isinstance(last, str) and last != grant_id
    handle, emitted = grants.emit_grant(
        records, document, trigger="change" if changed else "requested",
        previous=last if changed else None,
    )  # fmt: skip
    row.update(
        recorded=bool(handle.recorded), grant_id=emitted or grant_id, changed=changed,
        files=len(member["files"]), bytes=sum(f["bytes"] for f in member["files"]),
    )  # fmt: skip
    if member.get("incomplete"):
        row["incomplete"] = list(member["incomplete"])
    return row


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m fabric.cli._snapshot STATUS_FILE``, the request on stdin as JSON."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        sys.stderr.write("usage: python -m fabric.cli._snapshot STATUS_FILE < request.json\n")
        return 2
    try:
        payload = json.loads(sys.stdin.read())
    except ValueError:
        payload = None
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        sys.stderr.write("fabric snapshot worker: the request on stdin is not valid\n")
        return 2
    sys.stdout.write(json.dumps(record(payload, args[0]), sort_keys=True, default=str) + "\n")
    sys.stdout.flush()
    return 0


def run_worker(
    project: _project.Project, environ: Mapping[str, str], payload: Mapping[str, Any],
    status_file: Path,
) -> dict[str, Any]:  # fmt: skip
    """Start the worker with the environment ``fabric run`` gives a Python agent (the
    shell's ``FABRIC_*`` win), without the autoload."""
    plan = _run.Plan(added=dict(_project.compile_environment(project)))
    env, _ = _run.child_environment(environ, plan)
    for name in ("FABRIC_WIRE_AUTOLOAD", "FABRIC_RUN_ID", "FABRIC_WIRE_STATUS_FILE"):
        env.pop(name, None)
    with contextlib.suppress(OSError):
        status_file.unlink()
    try:
        result = subprocess.run(  # noqa: S603 - this interpreter, this package
            [sys.executable, "-m", "fabric.cli._snapshot", str(status_file)],
            env=env,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=WORKER_TIMEOUT_S,
            check=False,
            cwd=str(project.directory),
        )
    except subprocess.TimeoutExpired:
        return {"installed": False, "error": f"no answer in {WORKER_TIMEOUT_S:g} s"}
    except OSError as exc:
        return {"installed": False, "error": "the snapshot worker could not be started "
                                             f"({type(exc).__name__})"}  # fmt: skip
    lines = result.stdout.strip().splitlines()
    try:
        answer = json.loads(lines[-1]) if lines else None
    except ValueError:
        answer = None
    if isinstance(answer, dict):
        return answer
    # The worker died before it answered (an import error, a crash): say so, with its exit
    # code and the last line it wrote, instead of "capture did not install".
    tail = (result.stderr.strip().splitlines() or [""])[-1].strip()[:300]
    error = f"the snapshot worker exited with code {result.returncode} without an answer"
    return {"installed": False, "worker_failed": True,
            "error": error + (f" ({tail})" if tail else "")}  # fmt: skip


# ---------------------------------------------------------------- the last ids


def _state_path(project: _project.Project) -> Path:
    return project.state_dir / "state" / "snapshots.json"


def load_state(project: _project.Project) -> dict[str, str]:
    """``pth-`` id -> the last ``grt-`` id recorded for it (keyed ids only)."""
    try:
        data = json.loads(_state_path(project).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return {}
    return {k: v for k, v in files.items() if isinstance(k, str) and isinstance(v, str)}


def save_state(project: _project.Project, files: Mapping[str, str]) -> None:
    path = _state_path(project)
    with contextlib.suppress(OSError):
        _project.ensure_state_dir(project)
        path.parent.mkdir(parents=True, exist_ok=True)
        _runstate._write_private(
            path, json.dumps({"schema": STATE_SCHEMA, "files": dict(sorted(files.items()))},
                             indent=2) + "\n",
        )  # fmt: skip


# ---------------------------------------------------------------- the command


def _list_path(options: argparse.Namespace, project: _project.Project, cwd: Path) -> Path:
    if options.watched_paths:
        given = Path(options.watched_paths).expanduser()
        return given if given.is_absolute() else cwd / given
    privacy = str(project.resolved["capture.privacy"])
    if privacy == "profile-default":
        detail = "fabric.yaml names no capture policy (capture.privacy is profile-default)"
        raise CliError([Finding("FC-100", detail)])
    policy = Path(privacy).expanduser()
    return policy if policy.is_absolute() else project.directory / policy


def _not_recorded(answer: Mapping[str, Any]) -> Finding:
    if answer.get("error") == "no_id_key":
        return Finding("FC-102")
    raw = answer.get("status")
    status: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    reason_id, reason, fix = status.get("reason_id"), status.get("reason"), status.get("fix")
    if isinstance(reason, str):
        return Finding(
            "FC-104", f"{reason_id or 'FW-001'}: {reason}" + (f"; fix: {fix}" if fix else "")
        )
    error = answer.get("error")
    if answer.get("worker_failed"):
        return Finding("FC-104", f"{error}; run `fabric doctor`, which checks the same "
                                 "interpreter and configuration")  # fmt: skip
    if error == "records_inactive":
        return Finding("FC-104", "capture installed, but its records input did not start, so "
                                 "no record could be made; run `fabric doctor`")  # fmt: skip
    fallback = "capture did not install and gave no reason; run `fabric doctor`"
    return Finding("FC-104", str(error or fallback))


def run(  # noqa: PLR0912, PLR0915 - one branch per outcome the operator is told about
    options: argparse.Namespace,
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    *,
    worker: Callable[..., dict[str, Any]] = run_worker,
    now_ns: Callable[[], int] = time.time_ns,
) -> tuple[Report, list[str]]:
    """``fabric snapshot``."""
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    located = _config.discover(options.config, environ, cwd)
    project = _project.load(located, {}, environ)
    if options.project and options.project != project.name:
        raise CliError(
            [
                Finding(
                    "FC-032",
                    f"--project {options.project}, but {project.config_path} names {project.name}",
                )
            ]
        )
    source = _list_path(options, project, cwd)
    entries = load_watched(source)
    if not entries:
        raise CliError([Finding("FC-100", f"{source} lists none")])
    findings: list[Finding] = []
    lines: list[str] = [f"watched paths: {source} ({len(entries)} of class {SNAPSHOT_CLASS})"]
    report = Report("snapshot", findings=findings, config=located.to_json())
    report.data = {"project": project.name, "source": str(source), "files": []}
    if options.dry_run:
        for entry in entries:
            lines.append(f"  would read {entry['label']}: {entry['path']} ({entry['match']})")
            report.data["files"].append({"label": entry["label"], "match": entry["match"]})
        return report, lines
    label = f"snapshot-{now_ns() // 1_000_000_000}-{_random.token_hex(3)}"
    report.data["label"] = label
    state = load_state(project)
    payload = {"label": label, "entries": entries, "previous": state}
    _project.ensure_state_dir(project)
    status_file = project.state_dir / "state" / "snapshot.status.json"
    with contextlib.suppress(OSError):  # the worker writes why capture did not install here
        status_file.parent.mkdir(parents=True, exist_ok=True)
    answer = worker(project, environ, payload, status_file)
    rows = [row for row in answer.get("entries") or [] if isinstance(row, Mapping)]
    if not answer.get("installed") or (answer.get("error") and not rows):
        findings.append(_not_recorded(answer))
        report.exit_code = EXIT_FINDINGS
        lines.append("snapshot: nothing was recorded (see the finding)")
        return report, lines
    recorded = partial = 0

    def entries_path(row: Mapping[str, Any]) -> str:
        index = row.get("index")
        return entries[index]["path"] if type(index) is int and 0 <= index < len(entries) else "?"

    answered = {row.get("index") for row in rows}
    for number, entry in enumerate(entries):  # an entry the worker never reached is named
        if number not in answered:
            why = f"not reached ({answer.get('error') or 'the worker gave no answer for it'})"
            findings.append(Finding("FC-103", f"{entry['label']}: {entry['path']}: {why}"))
            lines.append(f"  {entry['label']}: not snapshotted ({why})")
            report.data["files"].append({"label": entry["label"], "recorded": False})
    for row in rows:
        name = str(row.get("label"))
        item: dict[str, Any] = {"label": name, "path_ref": row.get("path_ref"),
                                "recorded": bool(row.get("recorded"))}  # fmt: skip
        if not row.get("recorded"):
            why = str(row.get("error") or "the record was not accepted")
            findings.append(Finding("FC-103", f"{name}: {entries_path(row)}: {why}"))
            lines.append(f"  {name}: not snapshotted ({why})")
            report.data["files"].append(item)
            continue
        recorded += 1
        for field in ("grant_id", "files", "bytes", "changed", "incomplete"):
            if field in row:
                item[field] = row[field]
        report.data["files"].append(item)
        if isinstance(row.get("path_ref"), str) and isinstance(row.get("grant_id"), str):
            state[row["path_ref"]] = row["grant_id"]
        note = "changed since the last snapshot" if row.get("changed") else "recorded"
        lines.append(
            f"  {name}: {note}: {row.get('files')} file(s), {row.get('bytes')} bytes, "
            f"{row.get('path_ref')}, {row.get('grant_id')}"
        )
        if row.get("changed"):
            findings.append(Finding("FC-109", name))
        left_out = [_LEFT_OUT[r] for r in row.get("incomplete") or () if r in _LEFT_OUT]
        if left_out:
            partial += 1
            findings.append(Finding("FC-110", f"{name}: {entries_path(row)}: "
                                              + "; ".join(left_out)))  # fmt: skip
        if "size_limit" in (row.get("incomplete") or ()) and answer.get("contents") != "not_kept":
            findings.append(Finding("FC-108", f"{name}: at most {FILE_LIMIT // 1024} KiB of "
                                              "one file is kept, and the largest files' "
                                              "contents are left out until the document fits "
                                              "the run.permissions body limit"))  # fmt: skip
    report.data["contents"] = answer.get("contents")
    report.data["delivered"] = bool(answer.get("delivered"))
    if answer.get("contents") == "masked":
        mode = answer.get("contents_mode")
        lines.append(f"  contents: kept after masking (run.permissions is {mode} in the "
                     "capture policy), not verbatim")  # fmt: skip
    if recorded:
        save_state(project, state)
        if answer.get("contents") == "not_kept":
            findings.append(Finding("FC-107"))
        if not answer.get("delivered"):
            findings.append(Finding("FC-105"))
        elif recorded == len(entries) and not partial:
            findings.append(Finding("FC-106", f"run {label}"))
    if any(finding.severity == "error" for finding in findings):
        report.exit_code = EXIT_FINDINGS
    return report, lines


if __name__ == "__main__":
    raise SystemExit(main())
