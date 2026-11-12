# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §4.4 (R12): ``sdk/typescript/native/fabric_wire_abi.h`` is the frozen addon ABI.

The test reads the function table and the code list from the spec itself, compiles a
program against the header with a strict C11 compiler and checks that the header exports
exactly those functions (in order, with their argument counts) and those codes (fixed
negative values -1 .. -16, in the spec's order), plus the version and the bounds the spec
states."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HEADER = REPO_ROOT / "sdk" / "typescript" / "native" / "fabric_wire_abi.h"
SPEC = REPO_ROOT / "specs" / "055-typescript-wire-capture.md"
PROGRAM = r"""
#include <stdio.h>
#include "fabric_wire_abi.h"
#define PRINT_FUNCTION(name, argc) printf("F %s %d\n", #name, argc);
#define PRINT_CODE(name, value) printf("C %s %d\n", #name, value);
int main(void) {
  FABRIC_WIRE_FUNCTIONS(PRINT_FUNCTION)
  FABRIC_WIRE_CODES(PRINT_CODE)
  printf("K ABI_VERSION %d\n", FABRIC_WIRE_ABI_VERSION);
  printf("K NAPI_VERSION %d\n", FABRIC_WIRE_NAPI_VERSION);
  printf("K OK %d\n", FABRIC_WIRE_OK);
  printf("K FUNCTION_COUNT %d\n", FABRIC_WIRE_FUNCTION_COUNT);
  printf("K CODE_COUNT %d\n", FABRIC_WIRE_CODE_COUNT);
  printf("K FD_HANDLES %d\n", FABRIC_WIRE_FD_HANDLES);
  printf("K MAP_HANDLES %d\n", FABRIC_WIRE_MAP_HANDLES);
  printf("K MAX_MAP_BYTES %d\n", FABRIC_WIRE_MAX_MAP_BYTES);
  printf("K MAX_IO_BYTES %d\n", FABRIC_WIRE_MAX_IO_BYTES);
  printf("K MAX_NAME_BYTES %d\n", FABRIC_WIRE_MAX_NAME_BYTES);
  printf("K MAX_LIVE_ENVS %d\n", FABRIC_WIRE_MAX_LIVE_ENVS);
  printf("K DETACHED_RING %d\n", FABRIC_WIRE_DETACHED_RING);
  printf("K FILE_MODE %o\n", FABRIC_WIRE_FILE_MODE);
  printf("K FLOCK %d %d %d\n", FABRIC_WIRE_FLOCK_SHARED, FABRIC_WIRE_FLOCK_EXCLUSIVE,
         FABRIC_WIRE_FLOCK_UNLOCK);
  printf("K RECORD %d %d %d\n", FABRIC_WIRE_RECORD_READ, FABRIC_WIRE_RECORD_WRITE,
         FABRIC_WIRE_RECORD_UNLOCK);
  return 0;
}
"""


def _section() -> str:
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("### 4.4 Native addon ABI")
    return text[start : text.index("### 4.5", start)]


def spec_functions() -> list[tuple[str, int]]:
    """``(name, argument count)`` of every row of §4.4's function table, in order."""
    rows = re.findall(
        r"^\| `([A-Za-z0-9]+)\(([^)]*)\)[^`]*` \|", _section(), re.MULTILINE
    )
    return [
        (name, len([a for a in args.split(",") if a.strip()])) for name, args in rows
    ]


def spec_codes() -> list[str]:
    paragraph = _section().split("Codes are fixed negative integers:", 1)[1]
    paragraph = paragraph.split("No message strings", 1)[0]
    return re.findall(r"`([A-Z_]+)`", paragraph)


def _compile_and_run(tmp_path: Path) -> list[list[str]]:
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        if os.environ.get("CI"):
            pytest.fail("no C compiler: the ABI header test must run in CI")
        pytest.skip("no C compiler on this machine")
    source = tmp_path / "abi.c"
    source.write_text(PROGRAM, encoding="utf-8")
    binary = tmp_path / "abi"
    built = subprocess.run(
        [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
         f"-I{HEADER.parent}", "-o", str(binary), str(source)],
        capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip
    assert built.returncode == 0, built.stderr
    ran = subprocess.run(
        [str(binary)], capture_output=True, text=True, check=True, timeout=30
    )
    return [line.split() for line in ran.stdout.splitlines()]


def test_spec_tables_parse() -> None:
    assert len(spec_functions()) == 16
    assert len(spec_codes()) == 16


def test_header_compiles_and_matches_the_spec(tmp_path: Path) -> None:
    lines = _compile_and_run(tmp_path)
    functions = [(row[1], int(row[2])) for row in lines if row[0] == "F"]
    codes = [(row[1], int(row[2])) for row in lines if row[0] == "C"]
    constants = {row[1]: row[2:] for row in lines if row[0] == "K"}
    # Exactly the spec's functions, in its order, with its argument counts.
    assert functions == spec_functions()
    # Exactly the spec's codes, in its order, as the fixed values -1 .. -16.
    assert [name for name, _ in codes] == spec_codes()
    assert [value for _, value in codes] == list(range(-1, -17, -1))
    assert constants["ABI_VERSION"] == ["1"]  # abiVersion() returns 1
    assert constants["NAPI_VERSION"] == ["8"]  # C against Node-API version 8
    assert constants["OK"] == ["0"]
    assert constants["FUNCTION_COUNT"] == [str(len(functions))]
    assert constants["CODE_COUNT"] == [str(len(codes))]
    assert constants["FD_HANDLES"] == ["64"]  # 64 fd handles
    assert constants["MAP_HANDLES"] == ["8"]  # 8 map handles
    assert constants["MAX_MAP_BYTES"] == [str(64 * 1024)]  # length <= 64 KiB
    assert constants["MAX_IO_BYTES"] == [str(1024 * 1024)]  # dst/src <= 1 MiB
    assert constants["MAX_NAME_BYTES"] == ["255"]  # <= 255 bytes
    assert constants["MAX_LIVE_ENVS"] == ["1024"]  # at most 1,024 live
    assert constants["DETACHED_RING"] == ["1024"]  # the 1,024-entry ring
    assert constants["FILE_MODE"] == ["600"]  # openat(..., 0600)
    assert constants["FLOCK"] == ["0", "1", "2"]  # shared, exclusive, unlock
    assert constants["RECORD"] == ["0", "1", "2"]  # read, write, unlock


def test_header_states_the_spec_limits_in_its_own_words() -> None:
    """The bounds and operations named in §4.4 appear in the spec as the header has them."""
    section = _section()
    for phrase in ("64 fd handles", "8 map handles", "length ≤ 64 KiB", "≤ 1 MiB",
                   "≤ 255 bytes", "at most 1,024 live", "1,024-entry ring",
                   "Node-API version 8", "Returns `1`"):  # fmt: skip
        assert phrase in section, phrase
