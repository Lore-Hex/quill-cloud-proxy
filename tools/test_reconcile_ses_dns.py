from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def load_module() -> ModuleType:
    path = Path(__file__).with_name("reconcile_ses_dns.py")
    spec = importlib.util.spec_from_file_location("reconcile_ses_dns", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_plan_changes_creates_updates_and_ignores_matches() -> None:
    module = load_module()
    match = module.Record("a.example.", "CNAME", 300, ("target.example.",))
    stale = module.Record("b.example.", "TXT", 60, ('"old"',))
    desired_stale = module.Record("b.example.", "TXT", 300, ('"new"',))
    missing = module.Record("c.example.", "MX", 300, ("10 mx.example.",))

    changes = module.plan_changes(
        {(match.name, match.record_type): match, (stale.name, stale.record_type): stale},
        (match, desired_stale, missing),
    )

    assert changes == [("update", desired_stale), ("create", missing)]


def test_record_command_preserves_txt_quotes_and_spaces() -> None:
    module = load_module()
    record = module.Record(
        "mail.example.",
        "TXT",
        300,
        ('"v=spf1 include:amazonses.com ~all"',),
    )

    command = module.record_command(
        "create", record, project="project", zone="zone"
    )

    assert '--rrdatas="v=spf1 include:amazonses.com ~all"' in command
    assert "--type=TXT" in command


def test_declared_support_records_are_complete() -> None:
    module = load_module()
    config = Path(__file__).with_name("dns") / "ses-records.json"
    project, zone, records = module.load_config(config)

    assert project == "quill-cloud-proxy"
    assert zone == "trustedrouter-com"
    assert len([record for record in records if record.record_type == "CNAME"]) == 3
    assert {
        record.record_type
        for record in records
        if record.name == "mail.support.trustedrouter.com."
    } == {"MX", "TXT"}
