"""
BNG Blaster example configurations (examples/)

Every example configuration passes the configuration load. The
interfaces of the examples do not exist here, so BNG Blaster stops
after the configuration was loaded.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import subprocess

import pytest

import helpers

EXAMPLES = sorted(p for p in (helpers.REPO / "examples").rglob("*.json") if p.name != "run.json")


@pytest.mark.parametrize("path", EXAMPLES, ids=[str(p.relative_to(helpers.REPO / "examples")) for p in EXAMPLES])
def test_example_config_loads(path):
    result = subprocess.run([str(helpers.BNGBLASTER_BIN), "-C", str(path)],
                            capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    assert "Failed to load configuration" not in output, output
