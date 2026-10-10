#!/usr/bin/env python3
"""Generate/check the Go provider alias fixture from a trusted-router checkout.

python3 tools/sync_provider_alias_contract.py /path/to/quill-router [--check]
No router imports or third-party dependencies are required.
"""
import argparse
import ast
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("router", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = args.router / "src/trusted_router/routing.py"
    tables = {}
    for node in ast.parse(source.read_text()).body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        for target in targets:
            if isinstance(target, ast.Name) and target.id in {"_PROVIDER_ALIASES", "_PROVIDER_GROUP_ALIASES"}:
                tables[target.id] = ast.literal_eval(node.value)
    if len(tables) != 2:
        raise SystemExit("Expected both router alias tables; inspect routing.py before updating the generator")
    aliases = {alias: [provider] for alias, provider in tables["_PROVIDER_ALIASES"].items()}
    aliases.update(tables["_PROVIDER_GROUP_ALIASES"])
    content = json.dumps(aliases, indent=2, sort_keys=True) + "\n"
    fixture = Path(__file__).resolve().parents[1] / "enclave-go/internal/types/testdata/provider_aliases.json"
    if args.check:
        if fixture.read_text() != content:
            raise SystemExit("Router aliases drifted: regenerate provider_aliases.json and update NormalizeProviderFilters")
    else:
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(content)


if __name__ == "__main__":
    main()
