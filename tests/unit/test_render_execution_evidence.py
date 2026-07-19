from __future__ import annotations

import unittest

from scripts.render_execution_evidence import hc012_evidence_line


class RenderExecutionEvidenceTests(unittest.TestCase):
    def test_hc012_summary_distinguishes_repair_failure_and_blocker(self) -> None:
        self.assertIn("rejected hostile `PATH`", hc012_evidence_line("PASS"))
        self.assertIn("recorded a hostile `PATH` failure", hc012_evidence_line("FAIL"))
        self.assertIn("remained blocked", hc012_evidence_line("BLOCKED_BY_ACCESS"))


if __name__ == "__main__":
    unittest.main()
