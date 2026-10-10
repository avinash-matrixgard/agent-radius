"""A small JSON Schema validator for the subset the LLM schemas use.

Supported keywords: type, properties, required, additionalProperties (false),
items, enum, maxItems, maxLength. Anything else in a schema is ignored, so
keep LLM schemas inside this subset.
"""

from __future__ import annotations

from typing import Any

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


class SchemaError(ValueError):
    pass


def validate(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    expected = schema.get("type")
    if expected == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise SchemaError(f"{path}: expected integer")
    elif expected == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise SchemaError(f"{path}: expected number")
    elif expected is not None:
        if not isinstance(value, _TYPES[expected]):
            raise SchemaError(f"{path}: expected {expected}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaError(f"{path}: value not in enum")
    if isinstance(value, str) and "maxLength" in schema and len(value) > schema["maxLength"]:
        raise SchemaError(f"{path}: string longer than {schema['maxLength']}")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise SchemaError(f"{path}: more than {schema['maxItems']} items")
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(value):
                validate(item, item_schema, f"{path}[{i}]")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                raise SchemaError(f"{path}: missing required key {key!r}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(props)
            if extra:
                raise SchemaError(f"{path}: unexpected keys {sorted(extra)}")
        for key, sub in props.items():
            if key in value:
                validate(value[key], sub, f"{path}.{key}")
