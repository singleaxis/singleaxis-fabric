# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-3 agent: a plain, hand-written tool loop on an OpenAI Chat Completions model.

No framework and no agent SDK. It posts the model's HTTP API with httpx and runs two tools
in its own code:

- ``lookup_order(order_id)`` reads an order from the workspace;
- ``issue_refund(order_id, amount)`` needs the approval of another service first. The
  agent files a ticket with the fixture approval service (a clear business id it makes
  up, ``tkt-…``), waits for the answer, and then either runs the refund (a subprocess
  that appends to ``refunds.log``) or tells the model the refund was not approved.

Capture is switched on from outside (the autoload path on ``PYTHONPATH`` and ``FABRIC_*``
variables). The agent's one Fabric line is where it files a ticket: it records that it
asked, with the ticket as the control's clear id and the model's tool-call id
(``fabric.records.record_control``, spec 057 §4.6). Fabric records that line and never
answers, waits or decides; with capture off the call records nothing. The plan can turn
the line off (``record_request: false``): the agent side of the decision is then missing.

Everything the agent sees and does goes to its ledger (one JSON object per line), the
harness's ground truth: every model response, every tool call with its ticket, the
service's answer and the refund's exit code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "lookup_order",
            "description": "Look up an order by id: its customer, total and status.",
            "parameters": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "issue_refund",
            "description": "Refund an amount of an order to the customer. Needs approval.",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string"},
                    "amount": {"type": "number"},
                },
                "required": ["order_id", "amount"],
            },
        },
    },
]
WAIT_S = 15.0


class Ledger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def write(self, entry: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as out:
            out.write(json.dumps(entry, sort_keys=True) + "\n")


def record_request(ticket: str, call_id: str) -> None:
    """The agent's one Fabric line: it asked the approval service about this tool call."""
    try:
        from fabric import records  # noqa: PLC0415 - optional: the agent runs without Fabric
    except ImportError:
        return
    records.record_control(
        "approval",
        "request",
        "escalate",
        control_id=ticket,
        gated_tool_call_id=call_id,
        gated_kind="tool_call",
        stage="pre_tool",
        control="refund-approvals",
    )


class Agent:
    def __init__(self, plan: dict[str, Any]) -> None:
        self.plan = plan
        self.ledger = Ledger(Path(plan["ledger"]))
        self.http = httpx.Client(timeout=120)
        self.tickets = 0

    def run(self) -> dict[str, Any]:
        plan = self.plan
        headers = {"Content-Type": "application/json"}
        key_env = plan.get("api_key_env")
        if key_env:
            headers["Authorization"] = "Bearer " + os.environ[key_env]
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": plan["system"]},
            {"role": "user", "content": plan["task"]},
        ]
        results: list[dict[str, Any]] = []
        final = None
        for turn in range(int(plan["max_turns"])):
            body = {
                "model": plan["model"],
                "messages": messages,
                "tools": TOOLS,
                "tool_choice": "auto",
                "temperature": 0,
            }
            reply = self.http.post(
                plan["base_url"].rstrip("/") + "/chat/completions", json=body, headers=headers
            )
            self.ledger.write(
                {"type": "model", "turn": turn, "status": reply.status_code, "response": reply.text}
            )
            if reply.status_code != 200:  # noqa: PLR2004
                break
            message = reply.json()["choices"][0]["message"]
            kept = {"role": "assistant", "content": message.get("content")}
            if message.get("tool_calls"):
                kept["tool_calls"] = message["tool_calls"]
            messages.append(kept)
            if not message.get("tool_calls"):
                final = message.get("content")
                break
            for call in message["tool_calls"]:
                outcome = self.tool(call)
                results.append(outcome)
                messages.append(
                    {"role": "tool", "tool_call_id": call["id"], "content": outcome["result"]}
                )
        return {"final": final, "tools": results}

    def tool(self, call: dict[str, Any]) -> dict[str, Any]:
        name = call["function"]["name"]
        try:
            args = json.loads(call["function"].get("arguments") or "{}")
        except ValueError:
            args = {}
        entry: dict[str, Any] = {"type": "tool", "call_id": call["id"], "name": name}
        if name == "lookup_order":
            entry["result"] = self.lookup(str(args.get("order_id", "")))
        elif name == "issue_refund":
            entry.update(self.refund(call["id"], str(args.get("order_id", "")), args.get("amount")))
        else:
            entry["result"] = f"unknown tool {name}"
        self.ledger.write(entry)
        return {k: entry[k] for k in ("call_id", "name", "result", "exit_code") if k in entry}

    def lookup(self, order_id: str) -> str:
        path = Path("orders") / f"{order_id}.json"
        if not order_id.isalnum() or not path.is_file():
            return f"no order {order_id}"
        return path.read_text(encoding="utf-8")

    def refund(self, call_id: str, order_id: str, amount: Any) -> dict[str, Any]:
        try:
            value = float(amount)
        except (TypeError, ValueError):
            return {"result": "amount must be a number"}
        self.tickets += 1
        ticket = f"{self.plan['ticket_prefix']}-{self.tickets}"
        approvals = self.plan["approvals_url"].rstrip("/")
        filed = self.http.post(
            approvals + "/approvals", json={"ticket": ticket, "order_id": order_id, "amount": value}
        )
        if filed.status_code != 202:  # noqa: PLR2004
            return {"ticket": ticket, "result": "the approval service refused the ticket"}
        if self.plan.get("record_request", True):
            record_request(ticket, call_id)
        status = "pending"
        deadline = time.monotonic() + WAIT_S
        while status == "pending" and time.monotonic() < deadline:
            time.sleep(0.05)
            status = self.http.get(f"{approvals}/approvals/{ticket}").json().get("status")
        out: dict[str, Any] = {"ticket": ticket, "service_answer": status}
        if status != "approved":
            out["result"] = f"refund of {value:g} for order {order_id} was not approved"
            return out
        done = subprocess.run(  # noqa: S603 - the agent's own refund command
            [
                "/bin/sh",
                "-c",
                'printf "refund receipt order=%s amount=%s status=issued\\n" "$0" "$1"'
                " | tee -a refunds.log",
                order_id,
                f"{value:g}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        out["exit_code"] = done.returncode
        out["result"] = done.stdout.strip() if done.returncode == 0 else "refund failed"
        return out


def main() -> None:
    plan = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    outputs = Agent(plan).run()
    Path(plan["outputs"]).write_text(json.dumps(outputs, indent=1, sort_keys=True))
    print(json.dumps({"final": outputs["final"]}))


if __name__ == "__main__":
    main()
