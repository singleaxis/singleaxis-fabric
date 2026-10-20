# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared pieces of the matrix agents: scenarios, tools, the test image, results.

Nothing here imports or mentions Fabric: the agents are ordinary framework code
pointed at a model server through each framework's normal base-URL setting.

Every agent records what an outside observer of the agent would compare:
its final output, the exception it raised (type and message), and the sequence of
tool calls it executed. ``write_result`` serialises them canonically so a run with
capture and a run without it can be compared byte for byte.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import threading
import zlib
from collections.abc import Callable
from typing import Any

SCENARIOS: dict[str, dict[str, Any]] = {
    "simple": {"model": "fm-s2-p1-none", "stream": False},
    "stream": {"model": "fm-s2-p1-none", "stream": True},
    "parallel": {"model": "fm-s2-p2-none", "stream": False},
    "retry429": {"model": "fm-s2-p1-429", "stream": False},
    "disconnect": {"model": "fm-s2-p1-disc", "stream": True},
    "multimodal": {"model": "fm-s1-p1-none", "stream": False, "image": True},
    "long50": {"model": "fm-s50-p1-none", "stream": False},
    "node": {"model": "fm-s2-p1-none", "stream": False},
    "error400": {"model": "fm-s2-p1-400", "stream": False},
}
MAX_STEPS = 120  # framework iteration limits are raised to this for long runs

_LOCK = threading.Lock()
TOOL_LOG: list[list[Any]] = []


def secret() -> str:
    return os.environ.get("MATRIX_SECRET", "")


def prompt(extra: str = "") -> str:
    text = "What is the weather in Paris, in Fahrenheit? Use the tools."
    if secret():
        text += f" Reference {secret()}."
    return text + extra


def _record(name: str, args: dict[str, Any]) -> None:
    with _LOCK:
        TOOL_LOG.append([name, json.dumps(args, sort_keys=True)])


def get_weather(city: str) -> str:
    """Current temperature for a city, in Celsius."""
    _record("get_weather", {"city": city})
    doc: dict[str, Any] = {"city": city, "celsius": 18.5}
    if secret():
        doc["note"] = f"station {secret()}"
    return json.dumps(doc, sort_keys=True)


def c_to_f(celsius: float) -> str:
    """Convert Celsius to Fahrenheit."""
    _record("c_to_f", {"celsius": float(celsius)})
    return json.dumps({"fahrenheit": round(float(celsius) * 9 / 5 + 32, 2)})


TOOLS: list[Callable[..., str]] = [get_weather, c_to_f]

TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "get_weather": {"type": "object", "properties": {"city": {"type": "string"}},
                    "required": ["city"]},
    "c_to_f": {"type": "object", "properties": {"celsius": {"type": "number"}},
               "required": ["celsius"]},
}  # fmt: skip
TOOL_DESCRIPTIONS = {"get_weather": get_weather.__doc__, "c_to_f": c_to_f.__doc__}


def call_tool(name: str, args: dict[str, Any]) -> str:
    return {"get_weather": get_weather, "c_to_f": c_to_f}[name](**args)


def openai_tools() -> list[dict[str, Any]]:
    return [{"type": "function", "function": {"name": n, "description": TOOL_DESCRIPTIONS[n],
                                              "parameters": s}}
            for n, s in TOOL_SCHEMAS.items()]  # fmt: skip


def png_bytes(width: int = 160, height: int = 160, index: int = 0) -> bytes:
    """A real, incompressible PNG (deterministic noise), ~77 KiB (~103 KiB as base64)."""
    seed = hashlib.sha256(b"agent-matrix-image-%d" % index).digest()
    rows, block = [], seed
    for _ in range(height):
        data = b""
        while len(data) < width * 3:
            block = hashlib.sha256(block).digest()
            data += block
        rows.append(b"\x00" + data[: width * 3])

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))  # fmt: skip

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b""))  # fmt: skip


IMAGE_COUNT = 2  # two parts per request side: each fits the lowered body cap, the side not


def images() -> list[bytes]:
    return [png_bytes(index=i) for i in range(IMAGE_COUNT)]


def image_data_urls() -> list[str]:
    return ["data:image/png;base64," + base64.b64encode(b).decode() for b in images()]


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default="simple")
    parser.add_argument("--out", required=True)
    parser.add_argument("--variant", default="")
    ns = parser.parse_args()
    ns.cfg = dict(SCENARIOS[ns.scenario])
    ns.model = ns.cfg["model"]
    ns.stream = bool(ns.cfg.get("stream"))
    ns.image = bool(ns.cfg.get("image"))
    ns.openai_base = os.environ["MATRIX_OPENAI_BASE_URL"]  # http://127.0.0.1:PORT/v1
    ns.anthropic_base = os.environ["MATRIX_ANTHROPIC_BASE_URL"]  # http://127.0.0.1:PORT
    return ns


def exception_text(exc: BaseException) -> str:
    return f"{type(exc).__module__}.{type(exc).__qualname__}: {exc}"


def write_result(path: str, output: Any, exception: BaseException | None,
                 extra: dict[str, Any] | None = None) -> None:  # fmt: skip
    doc = {
        "output": output if isinstance(output, (str, int, float, list, dict, type(None)))
        else str(output),
        "exception": exception_text(exception) if exception is not None else None,
        "tool_calls": list(TOOL_LOG),
        **(extra or {}),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, sort_keys=True, indent=1, default=str)


def run(path: str, body: Callable[[], Any]) -> None:
    """Run the agent body; record its output or its exception, never re-raise."""
    output, error = None, None
    try:
        output = body()
    except BaseException as exc:  # noqa: BLE001 - the exception is the observable result
        error = exc
    write_result(path, output, error)
