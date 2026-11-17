"""The settle outbox alert reads the field the launcher exports workload lines in.

The Confidential Space launcher exports the workload's stdout and stderr as
jsonPayload.message (lower case). jsonPayload.MESSAGE carries only the
launcher's own lines, and Cloud Logging field names are case-sensitive, so a
clause on MESSAGE alone matches no enclave line.
"""

import re
import unittest
from pathlib import Path

MAIN_TF = Path(__file__).resolve().parent.parent / "infra/gcp/settle-outbox/main.tf"


def metric_filter(text):
    block = re.search(
        r'resource "google_logging_metric" "settle_outbox_attention" \{.*?filter\s*=\s*<<-EOT\n(.*?)\n\s*EOT',
        text,
        re.S,
    )
    if block is None:
        raise AssertionError("settle_outbox_attention filter not found")
    return block.group(1)


def clauses(text, field):
    return {
        line.strip()[len("OR ") :].strip().split(field, 1)[1]
        for line in metric_filter(text).splitlines()
        if field in line
    }


class SettleOutboxAlertFilter(unittest.TestCase):
    def test_every_sweep_clause_reads_the_lower_case_message_field(self):
        text = MAIN_TF.read_text()
        upper = clauses(text, "jsonPayload.MESSAGE")
        lower = clauses(text, "jsonPayload.message")
        self.assertTrue(upper, "expected MESSAGE clauses")
        self.assertEqual(upper, lower)

    def test_the_filter_names_the_lines_the_sweeper_writes(self):
        body = metric_filter(MAIN_TF.read_text())
        self.assertIn('jsonPayload.message:"settle_outbox.sweep_sender_refused"', body)
        self.assertIn(
            'jsonPayload.message=~"settle_outbox\\.sweep .*(dead|quarantined)=[1-9]"', body
        )

    def test_a_filter_with_only_upper_case_clauses_fails(self):
        text = MAIN_TF.read_text()
        broken = "\n".join(
            line for line in text.splitlines() if "jsonPayload.message" not in line
        )
        with self.assertRaises(AssertionError):
            self.assertEqual(
                clauses(broken, "jsonPayload.MESSAGE"),
                clauses(broken, "jsonPayload.message"),
            )


if __name__ == "__main__":
    unittest.main()
