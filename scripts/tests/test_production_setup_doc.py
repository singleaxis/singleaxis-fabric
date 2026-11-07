# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``docs/production-setup.md`` names only what the shipped deployment defines.

A user follows that page by copy and paste, so a wrong name fails at their
first command. These checks derive every name from the shipped files instead
of hard-coding it:

* every ``--network`` value, ``<project>_<name>`` network or volume and
  ``<project>-<service>-1`` container in the page is one the Compose files
  ``make up-prod-groups`` runs actually create (project ``name:`` and their
  ``networks`` / ``volumes`` / ``services``);
* every ``python -m fabric.reconstruct`` command parses with the reader's own
  argparse parser, never combines ``--content-key-file`` with ``--store-uri``
  (the reader exits 2) and passes ``--s3-*`` options only with ``--store-uri``;
* every ``make`` target the page runs or names exists in
  ``deploy/compose/Makefile``, every variable written to the Node's env file
  (``$FABRIC_ENV_FILE``, outside the checkout) is read by the Makefile, a
  Compose file or preflight, and every Compose file it names is shipped;
* the Makefile, preflight and verify read ``FABRIC_ENV_FILE``, and
  ``make up-prod-groups`` prints the project and ports that file sets;
* the capture-policy example keeps no argument, output or HTTP body in
  clear, and the masking recipe imports no private module;
* the agent-sandbox flags the page names (``--sandbox-peer``,
  ``--in-process-tool``) parse with the reader;
* no ``openssl x509 -CAcreateserial`` leaves its serial file in ``tls/``
  (mounted into the Node);
* no document runs AR-1 with the non-existent ``--mode production-replay``.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "production-setup.md"
COMPOSE_DIR = ROOT / "deploy" / "compose"
MAKEFILE = COMPOSE_DIR / "Makefile"
PREFLIGHT = COMPOSE_DIR / "preflight-prod.sh"
TEST_STORE_OVERLAY = "docker-compose.content-s3-local-tls.yml"

_FENCE = re.compile(r"^(\s*)```(\w*)\s*$")
_PLACEHOLDER = re.compile(r"<[^<>\n]+>")


class _ComposeLoader(yaml.SafeLoader):
    """Compose's !reset / !override merge tags as plain values."""


def _tagged(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)  # type: ignore[arg-type]


_ComposeLoader.add_multi_constructor("!", _tagged)


def _compose(path: Path) -> dict[str, Any]:
    loaded = yaml.load(path.read_text(encoding="utf-8"), _ComposeLoader)  # noqa: S506 - safe loader subclass
    assert isinstance(loaded, dict)
    return loaded


def _doc() -> str:
    return DOC.read_text(encoding="utf-8")


def _code_blocks(text: str) -> list[str]:
    """The bodies of the page's fenced code blocks (indented ones included)."""
    blocks: list[str] = []
    current: list[str] | None = None
    indent = ""
    for line in text.splitlines():
        fence = _FENCE.match(line)
        if fence and current is None:
            current, indent = [], fence.group(1)
        elif fence and current is not None:
            blocks.append("\n".join(current))
            current = None
        elif current is not None:
            current.append(line.removeprefix(indent))
    assert current is None, "unterminated code block"
    return blocks


def _balanced(line: str) -> bool:
    try:
        shlex.split(_PLACEHOLDER.sub("PLACEHOLDER", line), comments=True)
    except ValueError:  # a quoted string continues on the next line
        return False
    return True


def _shell_commands(text: str) -> Iterator[str]:
    """Logical shell lines of every code block: continuations and multi-line
    quoted strings joined, heredoc bodies skipped."""
    for block in _code_blocks(text):
        heredoc: str | None = None
        pending = ""
        for raw in block.splitlines():
            if heredoc is not None:
                if raw.strip() == heredoc:
                    heredoc = None
                continue
            line = pending + raw
            if line.rstrip().endswith("\\"):
                pending = line.rstrip()[:-1] + " "
                continue
            if not _balanced(line):
                pending = line + "\n"
                continue
            pending = ""
            marker = re.search(r"<<-?\s*'?(\w+)'?", line)
            if marker:
                heredoc = marker.group(1)
            yield line
        assert not pending and heredoc is None, (
            f"unterminated command in a code block: {pending!r}"
        )


def _words(command: str) -> list[str]:
    """shlex words of one command, placeholders made concrete, comment dropped."""
    concrete = _PLACEHOLDER.sub("PLACEHOLDER", command)
    return shlex.split(concrete, comments=True)


# --------------------------------------------------------------------------
# What the production Compose files define
# --------------------------------------------------------------------------


def _group_files() -> list[str]:
    """The Compose files ``make up-prod-groups`` merges with every option on:
    the auditd group, S3 content and the test store overlay."""
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is not installed")
    run = subprocess.run(  # noqa: S603
        [make, "-s", "-n", "-C", str(COMPOSE_DIR), "up-prod-groups"],
        env={
            "PATH": os.environ.get("PATH", ""),
            "FABRIC_CONTENT_BACKEND": "s3",
            "FABRIC_AUDITD_TOKEN_FILE": "/dev/null",
            "FABRIC_COMPOSE_EXTRA": TEST_STORE_OVERLAY,
        },
        capture_output=True,
        text=True,
        check=True,
    )
    line = next(x for x in run.stdout.splitlines() if " up -d --wait" in x)
    words = line.split()
    files = [words[i + 1] for i, w in enumerate(words) if w == "-f"]
    assert files[-1] == TEST_STORE_OVERLAY
    return files


def _production_names() -> dict[str, set[str]]:
    project = None
    networks: set[str] = set()
    volumes: set[str] = set()
    services: set[str] = set()
    for name in _group_files():
        doc = _compose(COMPOSE_DIR / name)
        # A later file's top-level name replaces an earlier one, as in Compose.
        project = doc.get("name", project)
        networks |= set(doc.get("networks") or {})
        volumes |= set(doc.get("volumes") or {})
        services |= set(doc.get("services") or {})
    assert project, "no Compose project name"
    # Services join the default network only when no networks: is declared.
    return {
        "project": {project},
        "networks": {f"{project}_{n}" for n in networks},
        "volumes": {f"{project}_{v}" for v in volumes},
        "containers": {f"{project}-{s}-1" for s in services},
    }


def test_production_project_is_what_the_page_says() -> None:
    names = _production_names()
    (project,) = names["project"]
    assert f"Compose project is `{project}`" in _doc()


def test_every_network_volume_and_container_name_exists() -> None:
    names = _production_names()
    (project,) = names["project"]
    text = _doc()
    network_flags = [
        word
        for command in _shell_commands(text)
        for flag, word in zip(_words(command), _words(command)[1:], strict=False)
        if flag == "--network"
    ]
    assert network_flags, "the page runs no container on the Node's network"
    for value in network_flags:
        assert value in names["networks"], (
            f"--network {value} is not a network Compose creates"
        )
    # Any compose-derived name in code or prose, e.g. fabric-node-local_fabric-node.
    derived = set(
        re.findall(r"\bfabric-node-[a-z0-9-]*[_-][a-z0-9_-]*[a-z0-9]\b", text)
    )
    allowed = (
        names["networks"] | names["volumes"] | names["containers"] | names["project"]
    )
    unknown = sorted(d for d in derived if d not in allowed)
    assert not unknown, (
        f"names not created by the production Compose project {project}: {unknown}"
    )


# --------------------------------------------------------------------------
# fabric.reconstruct commands
# --------------------------------------------------------------------------


def _reconstruct_commands() -> list[list[str]]:
    commands = []
    for command in _shell_commands(_doc()):
        words = _words(command)
        for i in range(len(words) - 2):
            if words[i : i + 3] == ["python", "-m", "fabric.reconstruct"]:
                commands.append(words[i + 3 :])
    return commands


def test_reconstruct_commands_parse_with_the_reader() -> None:
    main = pytest.importorskip("fabric.reconstruct.__main__")
    commands = _reconstruct_commands()
    assert commands, "the page runs no python -m fabric.reconstruct command"
    backends = set()
    for argv in commands:
        if argv[:1] == ["actions"]:
            parser, rest = main._actions_parser(), argv[1:]
        else:
            parser, rest = main._parser(), argv
        try:
            args = parser.parse_args(rest)
        except SystemExit as exc:  # the reader's usage error (exit 2)
            pytest.fail(
                f"python -m fabric.reconstruct {shlex.join(argv)}: exit {exc.code}"
            )
        assert not (args.content_key_file and args.store_uri), (
            "--content-key-file applies to --store-root only; with --store-uri the reader exits 2"
        )
        s3_options = args.s3_endpoint_url or args.s3_region or args.s3_path_style
        assert not s3_options or args.store_uri, "--s3-* options need --store-uri"
        assert args.tenant, "a content store needs --tenant"
        backends.add("s3" if args.store_uri else "dir" if args.store_root else "none")
        if args.store_uri and args.s3_endpoint_url:
            backends.add("s3-compatible")
            assert args.s3_endpoint_url.startswith("https://")
    assert {"s3", "s3-compatible", "dir"} <= backends, (
        "expected a command for AWS S3, an S3-compatible store and the directory backend"
    )


def test_reconstruct_flag_names_match_the_parser_help() -> None:
    """Every --flag the prose names is one the reader accepts."""
    main = pytest.importorskip("fabric.reconstruct.__main__")
    known = set()
    for parser in (main._parser(), main._actions_parser()):
        for action in parser._actions:
            known.update(action.option_strings)
    section = _doc().split("## 6. Read a run", 1)[1].split("## Docker Desktop", 1)[0]
    named = set(re.findall(r"`(--[a-z0-9-]+)", section))
    assert named, "section 6 names no reader option"
    assert named <= known, f"unknown reader options: {sorted(named - known)}"


# --------------------------------------------------------------------------
# make targets, .env variables and Compose files
# --------------------------------------------------------------------------


def _make_targets() -> set[str]:
    return set(
        re.findall(
            r"^([A-Za-z0-9_-]+):", MAKEFILE.read_text(encoding="utf-8"), re.MULTILINE
        )
    )


def test_every_make_target_exists() -> None:
    targets = _make_targets()
    used = set()
    for command in _shell_commands(_doc()):
        words = _words(command)
        for i, word in enumerate(words):
            if word != "make":
                continue
            rest = words[i + 1 :]
            j = 0
            while j < len(rest):
                if rest[j] in ("-C", "-f"):
                    j += 2
                elif rest[j].startswith("-") or "=" in rest[j]:
                    j += 1
                elif rest[j] in ("&&", "||", ";", "|"):
                    break
                else:
                    used.add(rest[j])
                    j += 1
    # Targets named in prose: `make up-prod`, `up-prod-groups`, `make down-prod-groups`.
    used |= set(re.findall(r"`make ([a-z0-9-]+)", _doc()))
    used |= set(re.findall(r"`make up-prod`/`([a-z0-9-]+)`", _doc()))
    assert "up-prod-groups" in used
    assert used <= targets, (
        f"make targets not in deploy/compose/Makefile: {sorted(used - targets)}"
    )


def _env_file_variables() -> set[str]:
    """Variables the page writes to the Node's env file (heredocs and echo)."""
    found: set[str] = set()
    for block in _code_blocks(_doc()):
        lines = block.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            heredoc = re.search(r"cat >>? \"\$FABRIC_ENV_FILE\" <<-?'?(\w+)'?", line)
            if heredoc:
                i += 1
                while lines[i].strip() != heredoc.group(1):
                    match = re.match(r"([A-Z][A-Z0-9_]*)=", lines[i])
                    if match:
                        found.add(match.group(1))
                    i += 1
            elif '"$FABRIC_ENV_FILE"' in line and line.lstrip().startswith("echo"):
                found.update(re.findall(r"\"([A-Z][A-Z0-9_]*)=", line))
            i += 1
    return found


def test_env_variables_are_read_by_the_deployment() -> None:
    written = _env_file_variables()
    assert {
        "FABRIC_COMPOSE_EXTRA",
        "FABRIC_CONTENT_BACKEND",
        "FABRIC_EBPF_SOURCE_ID",
    } <= written
    readers = [MAKEFILE, PREFLIGHT, *sorted(COMPOSE_DIR.glob("docker-compose*.yml"))]
    text = "\n".join(path.read_text(encoding="utf-8") for path in readers)
    unread = sorted(v for v in written if not re.search(rf"\b{v}\b", text))
    assert not unread, f".env variables nothing in deploy/compose reads: {unread}"
    makefile = MAKEFILE.read_text(encoding="utf-8")
    # The Make variables the page relies on to select overlays.
    for variable in ("FABRIC_COMPOSE_EXTRA", "FABRIC_CONTENT_BACKEND"):
        assert re.search(rf"^{variable} \?=", makefile, re.MULTILINE), variable


def test_every_named_compose_file_is_shipped() -> None:
    named = set(re.findall(r"\bdocker-compose[a-z0-9.-]*\.yml\b", _doc()))
    assert TEST_STORE_OVERLAY in named
    missing = sorted(n for n in named if not (COMPOSE_DIR / n).is_file())
    assert not missing, (
        f"Compose files the page names but deploy/compose lacks: {missing}"
    )


# --------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------


def _serial_file(words: list[str]) -> str | None:
    """Where ``openssl x509 -req`` writes its serial file, or None."""
    if words[:2] != ["openssl", "x509"] or "-CA" not in words:
        return None
    if "-CAserial" in words:
        return words[words.index("-CAserial") + 1]
    if "-CAcreateserial" in words:
        ca = PurePosixPath(words[words.index("-CA") + 1])
        return str(ca.with_suffix(".srl"))
    return None


def test_serial_file_never_lands_in_tls() -> None:
    signed = 0
    for command in _shell_commands(_doc()):
        words = _words(command)
        if words[:2] != ["openssl", "x509"] or "-CA" not in words:
            continue
        signed += 1
        serial = _serial_file(words)
        if serial is not None:
            assert "tls/" not in serial and not serial.startswith("tls"), (
                f"{shlex.join(words)} writes its serial file {serial} into tls/, "
                "which is mounted into the Node; use -set_serial or -CAserial outside tls/"
            )
    assert signed >= 2, "expected the Node's and the test store's certificates"


def test_serial_rule_catches_ca_createserial() -> None:
    words = shlex.split(
        "openssl x509 -req -in s.csr -CA tls/ca.crt -CAkey ca.key -CAcreateserial"
    )
    assert _serial_file(words) == "tls/ca.srl"
    words = shlex.split(
        "openssl x509 -req -CA tls/ca.crt -CAserial ca.srl -CAcreateserial"
    )
    assert _serial_file(words) == "ca.srl"


# --------------------------------------------------------------------------
# AR-1 commands anywhere in the documentation
# --------------------------------------------------------------------------


def test_no_document_runs_ar1_with_a_mode_it_lacks() -> None:
    offenders = []
    for path in [
        *ROOT.glob("docs/**/*.md"),
        *ROOT.glob("qualification/**/*.md"),
        ROOT / "README.md",
    ]:
        if "--mode production-replay" in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, (
        f"use `run_ar1.py --profile production --mode replay`: {offenders}"
    )


# --------------------------------------------------------------------------
# 0.11.2: env file outside the checkout, several stacks, safer policy, recipes
# --------------------------------------------------------------------------


def test_the_env_file_lives_outside_the_checkout() -> None:
    text = _doc()
    assert 'export FABRIC_ENV_FILE="$M/node.env"' in text
    writes = [
        line
        for block in _code_blocks(text)
        for line in block.splitlines()
        if re.search(r"(>>?|tee)\s*\"?\$FABRIC_REPO", line)
    ]
    assert not writes, f"the page writes into the checkout: {writes}"
    for script in (PREFLIGHT, COMPOSE_DIR / "verify-prod.sh"):
        assert 'ENV_FILE="${FABRIC_ENV_FILE:-.env}"' in script.read_text(
            encoding="utf-8"
        )
    makefile = MAKEFILE.read_text(encoding="utf-8")
    assert re.search(r"^FABRIC_ENV_FILE \?= \.env$", makefile, re.MULTILINE)
    assert "--env-file $(FABRIC_ENV_FILE)" in makefile


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
def test_up_prod_groups_echoes_the_env_file_ports(tmp_path: Path) -> None:
    env = tmp_path / "node.env"
    env.write_text(
        "COMPOSE_PROJECT_NAME=fabric-staging\nFABRIC_OTLP_GRPC_PORT=5317\n"
        "FABRIC_OTLP_HTTP_PORT=5318\nFABRIC_OTLP_CONTENT_PORT=5319\n"
        "FABRIC_EBPF_GRPC_PORT=5417\nFABRIC_CONTENT_BACKEND=s3\n",
        encoding="utf-8",
    )
    clean = {
        k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "COMPOSE_"))
    }
    out = subprocess.run(
        [
            "make",
            "-n",
            "-C",
            str(COMPOSE_DIR),
            "up-prod-groups",
            f"FABRIC_ENV_FILE={env}",
        ],
        capture_output=True,
        text=True,
        check=True,
        env=clean,
    ).stdout
    assert f"--env-file {env}" in out
    assert "Project fabric-staging" in out
    assert "agent 5317/5318, content 5319, ebpf 5417" in out
    default = subprocess.run(
        [
            "make",
            "-n",
            "-C",
            str(COMPOSE_DIR),
            "up-prod-groups",
            f"FABRIC_ENV_FILE={tmp_path / 'absent.env'}",
        ],
        capture_output=True,
        text=True,
        check=True,
        env=clean,
    ).stdout
    assert "agent 4317/4318, ebpf 4417" in default and "--env-file" not in default


def test_two_stack_variables_are_compose_settings() -> None:
    text = _doc()
    assert "### Two stacks on one host" in text
    compose = "\n".join(
        p.read_text(encoding="utf-8") for p in COMPOSE_DIR.glob("docker-compose*.yml")
    )
    for variable in (
        "FABRIC_OTLP_GRPC_PORT",
        "FABRIC_OTLP_HTTP_PORT",
        "FABRIC_OTLP_CONTENT_PORT",
        "FABRIC_EBPF_GRPC_PORT",
        "FABRIC_HEALTH_PORT",
        "FABRIC_METRICS_PORT",
    ):
        assert f"{variable}=" in text and "${" + variable in compose, variable
    assert "COMPOSE_PROJECT_NAME=" in text


def _policy_example() -> dict[str, Any]:
    import json  # noqa: PLC0415

    block = next(b for b in _code_blocks(_doc()) if "fabric.deployment-policy/v1" in b)
    body = block.split("<<EOF\n", 1)[1].rsplit("\nEOF", 1)[0].replace("$TENANT", "acme")
    return json.loads(body)


def test_the_policy_example_keeps_no_argv_output_or_body_in_clear() -> None:
    privacy = _policy_example()["privacy"]
    clear = {"retain_original", "original_plus_masked"}
    for role in (
        "terminal.argv",
        "terminal.stdout",
        "terminal.stderr",
        "network.request",
        "network.response",
    ):
        assert privacy[role] not in clear, role
    assert "withholds" in _doc() and "#masked-arguments-and-output" in _doc()


def test_the_masking_recipe_uses_public_api_only() -> None:
    recipes = [b for b in _code_blocks(_doc()) if "Transformation(" in b]
    assert recipes, "no masking recipe"
    for block in recipes:
        compile(block, "recipe", "exec")
        assert "._" not in block and "import _" not in block, block
        assert "install_from_env(transformations=" in block
    for doc in (
        ROOT / "docs/privacy-and-security.md",
        ROOT / "docs/production-setup.md",
    ):
        assert "fabric.wire._config" not in doc.read_text(encoding="utf-8"), doc


def test_the_redaction_examples_name_real_roles() -> None:
    roles_src = (ROOT / "sdk/python/src/fabric/_roles.py").read_text(encoding="utf-8")
    for path in (
        ROOT / "examples/redaction-service/README.md",
        ROOT / "contracts/redaction/v1/README.md",
    ):
        text = path.read_text(encoding="utf-8")
        for role in re.findall(r"X-Fabric-Role:? ?`?([a-z][a-z._]+[a-z])", text):
            assert f'"{role}"' in roles_src, (path.name, role)
        # wire capture's examples use the capture policy's roles, never an explicit-API one
        for block in _code_blocks(text):
            if "fabric.wire" in block or "X-Fabric-Role" in block:
                assert "model.request.messages" not in block, (path.name, block)


def test_the_sandbox_recipe_names_its_flags() -> None:
    text = _doc()
    section = text.split("### Agents that start containers", 1)[1].split("### ", 1)[0]
    for needle in (
        "/var/run/docker.sock",
        "--cgroup-parent=/fabric-sandboxes",
        "--sandbox-peer",
        "--in-process-tool",
        "EMIT_SANDBOX_CGROUP_ROOTS",
    ):
        assert needle in section or needle in text, needle
    main = pytest.importorskip("fabric.reconstruct.__main__")
    known = {o for a in main._actions_parser()._actions for o in a.option_strings}
    assert {"--sandbox-peer", "--in-process-tool"} <= known
    desktop = text.split("## Docker Desktop", 1)[1]
    assert "fabric-sandboxes" in desktop and "Clock steps" in desktop
    assert "FABRIC_CLOCK_UNCERTAINTY_MS" in desktop
