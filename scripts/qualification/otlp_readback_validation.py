"""Closed metadata parsing for controlled OTLP destination readback fixtures."""

from typing import Any


def json_attributes(record: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    values, types = {}, {}
    kinds = {"stringValue": "string_value", "intValue": "int_value"}
    for item in record["attributes"]:
        key, value = item["key"], item["value"]
        if key in values or len(value) != 1 or next(iter(value)) not in kinds:
            raise AssertionError(
                "duplicate key or unsupported projected attribute type"
            )
        kind = next(iter(value))
        raw = value[kind]
        if kind == "stringValue" and not isinstance(raw, str):
            raise AssertionError("invalid projected string attribute")
        if kind == "intValue":
            if isinstance(raw, bool) or not isinstance(raw, (int, str)):
                raise AssertionError("invalid projected integer attribute")
            try:
                parsed = int(raw)
            except ValueError as exc:
                raise AssertionError("invalid projected integer attribute") from exc
            if str(parsed) != str(raw) or not -(2**63) <= parsed < 2**63:
                raise AssertionError("invalid projected integer attribute")
        values[key], types[key] = str(raw), kinds[kind]
    return values, types


def protobuf_attributes(record: Any) -> tuple[dict[str, str], dict[str, str]]:
    values, types = {}, {}
    for item in record.attributes:
        kind = item.value.WhichOneof("value")
        if item.key in values or kind not in {"string_value", "int_value"}:
            raise AssertionError("duplicate key or unsupported evidence attribute type")
        values[item.key], types[item.key] = str(getattr(item.value, kind)), kind
    return values, types


def validate_metadata_container(resource: Any, scope: Any, record: Any) -> None:
    if record.body.WhichOneof("value") is not None:
        raise AssertionError("evidence OTLP body must be empty")
    if (
        resource.resource.attributes
        or resource.schema_url
        or scope.scope.attributes
        or scope.scope.name
        or scope.scope.version
        or scope.schema_url
    ):
        raise AssertionError("unexpected evidence resource or scope content")
