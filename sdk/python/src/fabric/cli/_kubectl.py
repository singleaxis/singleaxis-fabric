# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The cluster of the current kube context as ``fabric plan``, ``verify`` and ``doctor``
read it with ``--kubernetes`` (spec 058 §5.2, §5.7, §10.6).

Read-only by construction: this module can run ``kubectl get``, ``kubectl version``,
``kubectl logs`` and ``kubectl port-forward`` and nothing else (:data:`READ_VERBS`; a
test pins it). It never runs ``exec``, ``cp``, ``apply``, ``delete``, ``scale`` or
``rollout``, and it never restarts or changes a workload (I5). It contacts only the API
server of the current context, through ``kubectl`` (I4).

Secrets: presence and key names are read with a template that prints the key names
only, so no value reaches this process. The one exception is :meth:`Cluster.secret_value`,
which the reader needs for the id key (records carry keyed pseudonyms); the value is
returned to the caller, never printed, logged or written."""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import re
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any

from ._report import EXIT_PREREQUISITE, CliError, Finding

#: The only kubectl verbs this module runs.
READ_VERBS: frozenset[str] = frozenset({"get", "version", "logs", "port-forward"})
TIMEOUT_S = 30.0
_FORWARD_RE = re.compile(r"Forwarding from 127\.0\.0\.1:(\d+) ->")
_KEYS_TEMPLATE = '{{range $k, $v := .data}}{{$k}}{{"\\n"}}{{end}}'


class NotFound(Exception):  # noqa: N818 - a state, not an error
    """The object (or its namespace) does not exist."""


class Forbidden(Exception):  # noqa: N818 - a state the caller reports
    """The identity of the kube context may not read this."""


class Cluster:
    """``kubectl`` against the current kube context (``KUBECONFIG`` is honoured as
    kubectl honours it)."""

    def __init__(
        self,
        kubectl: str | None = None,
        runner: Callable[..., Any] = subprocess.run,
        popen: Callable[..., Any] = subprocess.Popen,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        found = kubectl or shutil.which(
            "kubectl", path=environ.get("PATH") if environ is not None else None
        )
        if not found:
            raise CliError([Finding("FC-120")], EXIT_PREREQUISITE)
        self.kubectl = found
        self.runner = runner
        self.popen = popen
        self.environ = dict(environ) if environ is not None else None

    # -- running kubectl

    def _run(self, args: Sequence[str], timeout: float = TIMEOUT_S) -> Any:
        if args[0] not in READ_VERBS:  # a programming error, never a user's
            raise AssertionError(f"kubectl {args[0]} is not a read")
        try:
            return self.runner(
                [self.kubectl, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                stdin=subprocess.DEVNULL,
                env=self.environ,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CliError([Finding("FC-103", type(exc).__name__)], EXIT_PREREQUISITE) from None

    @staticmethod
    def _problem(stderr: str) -> Exception:
        text = (stderr or "").strip()
        if "(NotFound)" in text or re.search(r"\bnot found\b", text):
            return NotFound(text[-200:])
        if "(Forbidden)" in text or "forbidden" in text.lower():
            return Forbidden(text.splitlines()[-1][:300] if text else "forbidden")
        last = text.splitlines()[-1][:300] if text else "kubectl failed"
        return CliError([Finding("FC-103", last)], EXIT_PREREQUISITE)

    def _json(self, args: Sequence[str]) -> Any:
        result = self._run(args)
        if result.returncode != 0:
            raise self._problem(result.stderr)
        try:
            return json.loads(result.stdout or "null")
        except ValueError:
            raise CliError(
                [Finding("FC-103", "kubectl returned no JSON")], EXIT_PREREQUISITE
            ) from None

    # -- reads

    def version(self) -> dict[str, Any]:
        """Client and server versions; reaching the server is the check that a context
        is selected and the API answers."""
        document = self._json(["version", "-o", "json"])
        return document if isinstance(document, dict) else {}

    def get(self, kind: str, name: str, namespace: str | None = None) -> dict[str, Any]:
        """One object; :class:`NotFound` or :class:`Forbidden`. Never a Secret."""
        _refuse_secret(kind)
        args = ["get", kind, name, "-o", "json"]
        if namespace:
            args += ["-n", namespace]
        document = self._json(args)
        if not isinstance(document, dict):
            raise NotFound(name)
        return document

    def find(self, kind: str, name: str, namespace: str | None = None) -> dict[str, Any] | None:
        try:
            return self.get(kind, name, namespace)
        except NotFound:
            return None

    def items(
        self,
        kind: str,
        namespace: str | None = None,
        selector: str | None = None,
        *,
        all_namespaces: bool = False,
    ) -> list[dict[str, Any]]:
        """The objects of a kind (an empty list when the kind is not served). Never
        Secrets."""
        _refuse_secret(kind)
        args = ["get", kind, "-o", "json"]
        if all_namespaces:
            args.append("--all-namespaces")
        elif namespace:
            args += ["-n", namespace]
        if selector:
            args += ["-l", selector]
        try:
            document = self._json(args)
        except NotFound:
            return []
        items = document.get("items") if isinstance(document, dict) else None
        return [item for item in items or [] if isinstance(item, dict)]

    def raw(self, path: str) -> Any:
        """``kubectl get --raw PATH``: one GET on the API server."""
        return self._json(["get", "--raw", path])

    def secret_keys(self, namespace: str, name: str) -> list[str] | None:
        """The key names of a Secret, None when it does not exist. The template prints
        names only: no value reaches this process."""
        result = self._run(
            ["get", "secret", name, "-n", namespace, "--ignore-not-found",
             "-o", f"go-template={_KEYS_TEMPLATE}"]
        )  # fmt: skip
        if result.returncode != 0:
            problem = self._problem(result.stderr)
            if isinstance(problem, NotFound):
                return None
            raise problem
        out = result.stdout or ""
        if not out.strip():
            # --ignore-not-found prints nothing for a missing Secret; a Secret without
            # data prints nothing either: tell them apart by name.
            named = self._run(["get", "secret", name, "-n", namespace, "--ignore-not-found",
                               "-o", "name"])  # fmt: skip
            return [] if (named.stdout or "").strip() else None
        return sorted(line for line in out.splitlines() if line)

    def secret_value(self, namespace: str, name: str, key: str) -> bytes | None:
        """One value of one Secret, for the reader's id key only. None when the Secret or
        the key is absent. Never printed or stored by this module."""
        if not re.fullmatch(r"[-._A-Za-z0-9]{1,253}", key):
            return None
        escaped = key.replace(".", "\\.")
        result = self._run(
            ["get", "secret", name, "-n", namespace, "--ignore-not-found",
             "-o", f"jsonpath={{.data.{escaped}}}"]
        )  # fmt: skip
        if result.returncode != 0:
            problem = self._problem(result.stderr)
            if isinstance(problem, NotFound):
                return None
            raise problem
        try:
            return base64.b64decode((result.stdout or "").strip(), validate=True) or None
        except (binascii.Error, ValueError):
            return None

    def logs(self, namespace: str, pod: str, container: str | None = None, tail: int = 400,
             *, previous: bool = False) -> str:  # fmt: skip
        """The last lines of a pod's log; empty when it has none or cannot be read."""
        args = ["logs", pod, "-n", namespace, f"--tail={tail}"]
        if container:
            args += ["-c", container]
        if previous:
            args.append("--previous")
        result = self._run(args)
        return (result.stdout or "") if result.returncode == 0 else ""

    @contextlib.contextmanager
    def port_forward(self, namespace: str, target: str, remote_port: int,
                     timeout: float = 15.0) -> Iterator[int]:  # fmt: skip
        """Forward a free loopback port to ``target`` (``svc/NAME`` or ``pod/NAME``) for
        the duration of the block, and close it. Yields the local port."""
        try:
            process = self.popen(
                [self.kubectl, "port-forward", "-n", namespace, target, f":{remote_port}",
                 "--address", "127.0.0.1"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                text=True, env=self.environ,
            )  # fmt: skip
        except OSError as exc:
            raise CliError([Finding("FC-103", type(exc).__name__)], EXIT_PREREQUISITE) from None
        found: list[int] = []

        def read() -> None:
            for line in process.stdout:
                match = _FORWARD_RE.search(line)
                if match:
                    found.append(int(match.group(1)))
                    return

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            deadline = time.monotonic() + timeout
            while not found and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if not found:
                error = ""
                if process.poll() is not None and process.stderr is not None:
                    tail = (process.stderr.read() or "").strip().splitlines()[-1:]
                    error = tail[0][:300] if tail else ""
                raise CliError(
                    [Finding("FC-128", f"{namespace}/{target} port {remote_port}"
                             + (f": {error}" if error else ""))],
                    EXIT_PREREQUISITE,
                )  # fmt: skip
            _wait_listening(found[0])
            yield found[0]
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - kubectl ignores SIGTERM
                process.kill()
            for stream in (process.stdout, process.stderr):
                with contextlib.suppress(Exception):
                    if stream is not None:
                        stream.close()


def _refuse_secret(kind: str) -> None:
    if kind.lower().split(".")[0] in ("secret", "secrets"):
        raise AssertionError("Secrets are read by key name only (secret_keys)")


def _wait_listening(port: int, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.5):
            return
        time.sleep(0.05)


__all__ = ["READ_VERBS", "Cluster", "Forbidden", "NotFound"]
