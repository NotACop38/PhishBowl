"""A tiny, dependency-free JSON Schema validator (PRD §6.6).

Phishbowl's SOAR exports each ship an *expected schema* — a real JSON Schema
(draft 2020-12) document under :mod:`phishbowl.export.schemas` — and a validation
test asserts every emitted artifact conforms to it (Phase 6 DoD). The offline-first
ethos means ``make test`` stays self-contained and key-free, so rather than pull in
a third-party validator we implement exactly the keyword subset our two schemas
use. The supported vocabulary is deliberately small and fully covered by
``tests/test_export.py`` (positive *and* negative cases), so the validator is
trustworthy without becoming a maintenance burden.

Supported keywords: ``type`` (single or list), ``enum``, ``const``, ``required``,
``properties``, ``additionalProperties`` (bool or schema), ``minProperties``,
``propertyNames``, ``items``, ``minItems``/``maxItems``, ``minLength``/``maxLength``,
``pattern``, ``anyOf``/``allOf``, and local ``$ref`` (``#/...``) resolved against
``$defs``. That is everything the XSOAR and Sentinel schemas need and nothing more.

:func:`validate` returns a list of human-readable error strings; an empty list
means the instance conforms. It never touches the network and has no side effects.
"""

from __future__ import annotations

import re
from typing import Any

# JSON type name -> Python predicate. ``bool`` is a subclass of ``int`` in Python,
# so it is explicitly excluded from ``integer``/``number`` (a JSON boolean is not a
# JSON number).
_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _resolve(ref: str, root: dict[str, Any]) -> dict[str, Any]:
    """Resolve a local ``#/...`` JSON Pointer ``$ref`` against the schema root."""
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported $ref {ref!r}: only local '#/...' refs are supported")
    node: Any = root
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[token]
    return node


def validate(
    instance: Any,
    schema: dict[str, Any],
    *,
    root: dict[str, Any] | None = None,
    path: str = "$",
) -> list[str]:
    """Validate ``instance`` against ``schema``; return a list of error strings.

    An empty list means the instance conforms. ``root`` (defaulting to ``schema``)
    is the document ``$ref`` pointers resolve against; ``path`` is the JSON-path
    breadcrumb used in error messages.
    """
    root = schema if root is None else root
    errors: list[str] = []

    if "$ref" in schema:
        # Our schemas use standalone refs (no sibling keywords alongside $ref),
        # which matches pre-2019 semantics and keeps resolution unambiguous.
        return validate(instance, _resolve(schema["$ref"], root), root=root, path=path)

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']!r}")

    if "type" in schema:
        types = schema["type"]
        types = [types] if isinstance(types, str) else types
        if not any(_TYPE_CHECKS[t](instance) for t in types):
            got = "null" if instance is None else type(instance).__name__
            errors.append(f"{path}: expected type {schema['type']!r}, got {got}")
            # The type is wrong, so type-specific checks below would only add noise.
            return errors

    if isinstance(instance, str):
        errors += _check_string(instance, schema, path)
    if isinstance(instance, list):
        errors += _check_array(instance, schema, root, path)
    if isinstance(instance, dict):
        errors += _check_object(instance, schema, root, path)

    for combiner in ("anyOf", "allOf"):
        if combiner in schema:
            errors += _check_combiner(combiner, instance, schema[combiner], root, path)

    return errors


def _check_string(instance: str, schema: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    if "minLength" in schema and len(instance) < schema["minLength"]:
        errors.append(f"{path}: string shorter than minLength {schema['minLength']}")
    if "maxLength" in schema and len(instance) > schema["maxLength"]:
        errors.append(f"{path}: string longer than maxLength {schema['maxLength']}")
    if "pattern" in schema and re.search(schema["pattern"], instance) is None:
        errors.append(f"{path}: {instance!r} does not match pattern {schema['pattern']!r}")
    return errors


def _check_array(
    instance: list[Any], schema: dict[str, Any], root: dict[str, Any], path: str
) -> list[str]:
    errors: list[str] = []
    if "minItems" in schema and len(instance) < schema["minItems"]:
        errors.append(f"{path}: array has fewer than minItems {schema['minItems']}")
    if "maxItems" in schema and len(instance) > schema["maxItems"]:
        errors.append(f"{path}: array has more than maxItems {schema['maxItems']}")
    if "items" in schema:
        for i, item in enumerate(instance):
            errors += validate(item, schema["items"], root=root, path=f"{path}[{i}]")
    return errors


def _check_object(
    instance: dict[str, Any], schema: dict[str, Any], root: dict[str, Any], path: str
) -> list[str]:
    errors: list[str] = []
    if "minProperties" in schema and len(instance) < schema["minProperties"]:
        errors.append(f"{path}: object has fewer than minProperties {schema['minProperties']}")

    for required in schema.get("required", []):
        if required not in instance:
            errors.append(f"{path}: missing required property {required!r}")

    props = schema.get("properties", {})
    for key, subschema in props.items():
        if key in instance:
            errors += validate(instance[key], subschema, root=root, path=f"{path}.{key}")

    additional = schema.get("additionalProperties", True)
    if additional is not True:
        for key, value in instance.items():
            if key in props:
                continue
            if additional is False:
                errors.append(f"{path}: additional property {key!r} is not allowed")
            else:  # additionalProperties is itself a schema applied to every extra key
                errors += validate(value, additional, root=root, path=f"{path}.{key}")

    if "propertyNames" in schema:
        for key in instance:
            errors += validate(key, schema["propertyNames"], root=root, path=f"{path}.<{key}>")

    return errors


def _check_combiner(
    combiner: str,
    instance: Any,
    subschemas: list[dict[str, Any]],
    root: dict[str, Any],
    path: str,
) -> list[str]:
    if combiner == "anyOf":
        if any(not validate(instance, s, root=root, path=path) for s in subschemas):
            return []
        return [f"{path}: does not match any schema in anyOf"]
    # allOf
    errors: list[str] = []
    for subschema in subschemas:
        errors += validate(instance, subschema, root=root, path=path)
    return errors
