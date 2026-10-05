"""Mutated controlled evidence must never earn a successful readback claim."""

import importlib.util
import json
from pathlib import Path

import pytest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)


def load(name):
    path = Path(__file__).parents[1] / "qualification" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("verifier", ["synthetic", "sol", "custom"])
@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "body",
        "resource",
        "scope",
        "scope_name",
        "scope_version",
        "scope_schema",
        "resource_schema",
        "duplicate",
        "extra",
        "unsupported",
        "type",
        "missing",
        "value",
    ],
)
def test_exact_metadata_readback(tmp_path, verifier, mutation):
    attrs = {"record_id": "evt-example", "source_sequence": "1"}
    types = {"record_id": "string_value", "source_sequence": "int_value"}
    expected = {
        "event_name": "agent.evidence.content",
        "attributes": attrs,
        "attribute_types": types,
    }
    request = ExportLogsServiceRequest()
    resource = request.resource_logs.add()
    scope = resource.scope_logs.add()
    record = scope.log_records.add(event_name=expected["event_name"])
    for key, value in attrs.items():
        item = record.attributes.add(key=key)
        setattr(
            item.value, types[key], int(value) if types[key] == "int_value" else value
        )
    if mutation == "body":
        record.body.string_value = "UNEXPECTED_CONTENT"
    elif mutation in {"resource", "scope"}:
        container = resource.resource if mutation == "resource" else scope.scope
        container.attributes.add(
            key="private"
        ).value.string_value = "UNEXPECTED_CONTENT"
    elif mutation == "scope_name":
        scope.scope.name = "UNEXPECTED_CONTENT"
    elif mutation == "scope_version":
        scope.scope.version = "UNEXPECTED_CONTENT"
    elif mutation == "scope_schema":
        scope.schema_url = "UNEXPECTED_CONTENT"
    elif mutation == "resource_schema":
        resource.schema_url = "UNEXPECTED_CONTENT"
    elif mutation == "duplicate":
        record.attributes.add().CopyFrom(record.attributes[0])
    elif mutation == "extra":
        record.attributes.add(key="private").value.string_value = "UNEXPECTED_CONTENT"
    elif mutation == "unsupported":
        record.attributes.add(key="private").value.bool_value = True
    elif mutation == "type":
        record.attributes[1].value.string_value = "1"
    elif mutation == "missing":
        del record.attributes[1]
    elif mutation == "value":
        record.attributes[1].value.int_value = 2
    sink = tmp_path / "sink"
    sink.mkdir()
    (sink / "one.otlp").write_bytes(request.SerializeToString())
    projected = {
        "resourceLogs": [
            {
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "eventName": expected["event_name"],
                                "attributes": [
                                    {
                                        "key": key,
                                        "value": {
                                            "stringValue"
                                            if types[key] == "string_value"
                                            else "intValue": value
                                        },
                                    }
                                    for key, value in attrs.items()
                                ],
                            }
                        ]
                    }
                ]
            }
        ]
    }
    projection = tmp_path / "otlp-metadata.json"
    projection.write_text(json.dumps(projected))
    if verifier == "synthetic":
        module = load("verify_synthetic_sink_readback")
        report = {"cases": [{"fault": "clean", "expected_sink_records": [expected]}]}

        def invoke():
            return module.verify(report, sink)
    elif verifier == "sol":
        module = load("verify_sol_sink_readback")

        def invoke():
            return module.verify(tmp_path, sink)
    else:
        module = load("run_custom_agent_node_pilot")

        def invoke():
            return module.readback(sink, module.expected_records(projection))

    if mutation is None:
        invoke()
    else:
        with pytest.raises(AssertionError):
            invoke()


@pytest.mark.parametrize(
    "mutation", ["duplicate", "bool", "double", "two_types", "bad_integer"]
)
def test_projected_attributes_are_closed(mutation):
    from scripts.qualification.otlp_readback_validation import json_attributes

    item = {"key": "record_id", "value": {"stringValue": "evt-example"}}
    record = {"attributes": [item]}
    if mutation == "duplicate":
        record["attributes"].append(item)
    elif mutation == "bool":
        item["value"] = {"intValue": True}
    elif mutation == "double":
        item["value"] = {"doubleValue": 1.0}
    elif mutation == "two_types":
        item["value"]["intValue"] = "1"
    else:
        item["value"] = {"intValue": "1.0"}
    with pytest.raises(AssertionError):
        json_attributes(record)


def test_empty_custom_readback_does_not_qualify(tmp_path):
    module = load("run_custom_agent_node_pilot")
    with pytest.raises(AssertionError, match="empty"):
        module.readback(tmp_path, {})
