"""
BNG Blaster JSON schema (schemas/bngblaster-config.json)

Every example configuration and every configuration of the documentation
(JSON code blocks with top level sections only) validates against the
schema. Like BNG Blaster, the schema rejects unknown attributes except
those starting with "_".

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import re

import pytest

import helpers

jsonschema = pytest.importorskip("jsonschema")

SCHEMA = json.loads((helpers.REPO / "schemas/bngblaster-config.json").read_text())
VALIDATOR = jsonschema.Draft201909Validator(SCHEMA)
EXAMPLES = sorted(p for p in (helpers.REPO / "examples").rglob("*.json") if p.name != "run.json")
CODE_BLOCK = re.compile(r"^\.\. code-block:: json\s*\n((?:[ \t]*\n|[ \t]+.*\n)+)", re.M)


def placeholder(value):
    """Section templates of the configuration reference ({} or [])."""
    if isinstance(value, dict):
        return not value or any(placeholder(v) for v in value.values())
    if isinstance(value, list):
        return not value or any(placeholder(v) for v in value)
    return False


def doc_configs():
    configs = []
    for path in sorted((helpers.REPO / "docsrc/sources").rglob("*.rst")):
        for idx, block in enumerate(CODE_BLOCK.findall(path.read_text())):
            try:
                config = json.loads(block)
            except ValueError:
                continue
            if isinstance(config, dict) and set(config) <= set(SCHEMA["properties"]) and not placeholder(config):
                configs.append(pytest.param(config, id="%s-%d" % (
                    path.relative_to(helpers.REPO / "docsrc/sources"), idx)))
    return configs


def errors(config):
    # The most relevant error of each, also within oneOf (object or list).
    return ["%s: %s" % ("/".join(str(p) for p in e.absolute_path), e.message)
            for e in (jsonschema.exceptions.best_match([e]) for e in VALIDATOR.iter_errors(config))]


def test_schema_valid():
    jsonschema.Draft201909Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("path", EXAMPLES, ids=[str(p.relative_to(helpers.REPO / "examples")) for p in EXAMPLES])
def test_schema_example(path):
    assert errors(json.loads(path.read_text())) == []


@pytest.mark.parametrize("config", doc_configs())
def test_schema_doc_config(config):
    assert errors(config) == []


@pytest.mark.parametrize("config,valid", [
    ({"sessions": {"count": 1, "_comment": "ignored"}}, True),
    ({"sessions": {"count": 1, "session-time": 0}}, False),
    ({"pppoe": {"sessions": 1, "max-outstanding": 1, "start-rate": 1, "stop-rate": 1}}, True),
    ({"interfaces": {"network": [{"interface": "eth0", "adress": "10.0.0.1/24"}]}}, False),
    ({"l2tp-server": [{"name": "LNS", "address": "10.0.0.1", "lcp-padding": 1400}]}, True),
    ({"l2tp-server": [{"name": "LNS", "address": "10.0.0.1", "lcp-padding": 1401}]}, False),
    ({"streams": [{"name": "S", "type": "ipv4", "pps": 0.1}]}, True),
    ({"streams": [{"name": "S", "type": "ipv4", "pps": 0}]}, False),
    ({"icmp-client": [{"destination-address": "10.0.0.1", "interval": 0}]}, False),
    ({"isis": [{"instance-id": 1, "external-auto-refresh": True}]}, True),
    ({"ospf": [{"instance-id": 1, "external": {"auto-refresh": True}}]}, True),
    ({"pppoe": {"max-payload": 0}, "igmp": {"zapping-interval": 0, "multicast-traffic-length": 0}}, True),
    ({"igmp": {"multicast-traffic-length": 64}}, False),
], ids=["underscore", "misplaced", "pppoe-deprecated", "misspelled", "lcp-padding-max",
        "lcp-padding-above-max", "pps", "pps-zero", "icmp-interval-zero", "isis-auto-refresh",
        "ospf-auto-refresh", "zero-disabled", "multicast-traffic-length-small"])
def test_schema_attributes(config, valid):
    assert (errors(config) == []) == valid, errors(config)
