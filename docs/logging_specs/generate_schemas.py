#!/usr/bin/env python3
"""Generate JSON schemas from Pydantic models.

Run from the docs/logging_specs directory:
    python generate_schemas.py

Outputs .schema.json files next to each .py file.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


def load_module_from_path(module_name: str, file_path: Path) -> ModuleType:
    """Load a Python module from a file path without requiring __init__.py.

    Args:
        module_name: Name to register the module under in sys.modules.
        file_path: Path to the Python file to load.

    Returns:
        The loaded module object.
    """
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def generate_schema(model_class: type[Any], output_path: Path) -> None:
    """Generate JSON schema for a Pydantic model and write to file.

    Args:
        model_class: A Pydantic model class with model_json_schema() method.
        output_path: Path where the JSON schema file will be written.
    """
    schema = model_class.model_json_schema()
    with open(output_path, "w") as f:
        json.dump(schema, f, indent=2)
        f.write("\n")
    print(f"Generated: {output_path}")


def main() -> None:
    base_dir = Path(__file__).parent

    # Load and generate audit schemas
    audit_dir = base_dir / "audit"
    operations = load_module_from_path("operations", audit_dir / "operations.py")
    decisions = load_module_from_path("decisions", audit_dir / "decisions.py")
    auth = load_module_from_path("auth", audit_dir / "auth.py")
    generate_schema(operations.OperationEvent, audit_dir / "operations.schema.json")
    generate_schema(decisions.DecisionEvent, audit_dir / "decisions.schema.json")
    generate_schema(auth.AuthEvent, audit_dir / "auth.schema.json")

    # Load and generate system schemas
    system_dir = base_dir / "system"
    system = load_module_from_path("system_events", system_dir / "system.py")
    config_history = load_module_from_path("config_history", system_dir / "config_history.py")
    policy_history = load_module_from_path("policy_history", system_dir / "policy_history.py")
    generate_schema(system.SystemEvent, system_dir / "system.schema.json")
    generate_schema(config_history.ConfigHistoryEvent, system_dir / "config_history.schema.json")
    generate_schema(policy_history.PolicyHistoryEvent, system_dir / "policy_history.schema.json")

    print("\nAll schemas generated successfully!")


if __name__ == "__main__":
    main()
