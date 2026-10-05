# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate freshly built TypeScript output with the actual content-v1 contracts."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.contracts.validate_content_contracts import validate_content_document

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "sdk" / "typescript"


@pytest.fixture(scope="module")
def emitted_documents(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    if (
        not shutil.which("node")
        or not (SDK / "node_modules" / ".bin" / "tsup").exists()
    ):
        pytest.skip(
            "requires Node and npm ci in sdk/typescript for built-artifact contract test"
        )
    subprocess.run(
        ["npm", "run", "build"], cwd=SDK, check=True, capture_output=True, timeout=90
    )
    store = tmp_path_factory.mktemp("typescript-content-contract")
    code = r"""
import { Fabric, LocalFilesystemContentStore, TranscriptManifest, buildContentDescriptor } from './dist/index.js';
const store = new LocalFilesystemContentStore(process.argv[1], 'acme');
const fabric = new Fabric({tenantId: 'acme', agentId: 'agent', contentCapture: {store, roles: 'all', durability: 'inline'}});
let uri;
fabric.decision({sessionId:'session', requestId:'request'}, d => {
  d.remember({kind:'semantic',content:'memory write'});
  d.recall({kind:'semantic',key:'key',content:'memory read'});
  d.recordSideEffect({type:'api_mutation',targetSystem:'crm',operation:'update',sideEffectId:'effect-1',requestPayload:'request',resultPayload:'result'});
  uri=d.contentManifestUri;
});
const manifest=store.readManifest(uri);
let emptyTextUri;
fabric.decision({sessionId:'session',requestId:'empty-text'},d=>{
  d.recordContext('empty.txt','');
  emptyTextUri=d.contentManifestUri;
});
await fabric.close();
const emptyText=store.readManifest(emptyTextUri);
const emptyTextBytes=store.read(emptyText.items[0].ref).length;
const mixed=new TranscriptManifest({manifestId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',tenantId:'acme',agentId:'agent',decisionId:'decision',producer:{name:'test',version:'1',language:'typescript'},rolesEnabled:new Set(['context.file','tool.call.result'])});
for (const [role,status] of [['context.file','stored'],['tool.call.result','failed']]) {
  const item={sequence:0,role,status};
  if(status==='stored') {
    item.descriptor=buildContentDescriptor({tenantId:'acme',role,content:'content',mediaType:'text/plain',source:'caller',status,bindings:{},payloadMaxBytes:100}).descriptor;
    item.ref=store.refFor(item.descriptor.digest.slice(7));
  }
  mixed.add(item);
}
process.stdout.write(JSON.stringify({manifest,mixed:mixed.toJSON(),emptyText,emptyTextBytes}));
"""
    result = subprocess.run(
        ["node", "--input-type=module", "-e", code, str(store)],
        cwd=SDK,
        check=True,
        text=True,
        capture_output=True,
        timeout=30,
    )
    return json.loads(result.stdout)


def schemas() -> dict[str, Any]:
    folder = ROOT / "contracts" / "content" / "v1" / "schema"
    return {
        f"schema/{path.name}": json.loads(path.read_text())
        for path in folder.glob("*.json")
    }


def test_typescript_manifest_matches_schema_and_semantics(
    emitted_documents: dict[str, Any],
) -> None:
    validate_content_document(emitted_documents["manifest"], schemas())


def test_typescript_failed_roles_are_not_observed(
    emitted_documents: dict[str, Any],
) -> None:
    document = emitted_documents["mixed"]
    validate_content_document(document, schemas())
    assert document["coverage"]["roles_observed"] == ["context.file"]
    assert document["completeness"] == {"stored": 1, "failed": 1}


def test_typescript_memory_and_side_effect_descriptor_bindings(
    emitted_documents: dict[str, Any],
) -> None:
    document = emitted_documents["manifest"]
    assert {item["role"] for item in document["items"]} == {
        "memory.write.content",
        "memory.read.content",
        "side_effect.request",
        "side_effect.result",
    }
    for item in document["items"]:
        validate_content_document(item["descriptor"], schemas())
        assert "direction" not in item["descriptor"]["bindings"]
        assert "side_effect_id" not in item["descriptor"]["bindings"]


def test_typescript_explicit_empty_text_is_still_an_observation(
    emitted_documents: dict[str, Any],
) -> None:
    document = emitted_documents["emptyText"]
    validate_content_document(document, schemas())
    assert document["completeness"] == {"stored": 1}
    assert document["coverage"]["roles_observed"] == ["context.file"]
    assert document["items"][0]["descriptor"]["byte_length"] == 0
    assert emitted_documents["emptyTextBytes"] == 0
