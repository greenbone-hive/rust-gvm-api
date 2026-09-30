"""Regression coverage for the fail-closed sbomqs quality threshold."""

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from scripts.check_sbom_quality import check_report, main


class SbomQualityTests(unittest.TestCase):
    def write_report(self, report: object) -> Path:
        directory = tempfile.TemporaryDirectory(prefix="sbom-quality-")
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def test_threshold_is_inclusive(self) -> None:
        failures = check_report(
            {"files": [{"file_name": "gateway.cdx.json", "sbom_quality_score": 8.3}]},
            8.3,
        )
        self.assertEqual(failures, [])

    def test_below_threshold_blocks(self) -> None:
        report = self.write_report(
            {"files": [{"file_name": "gateway.cdx.json", "sbom_quality_score": 8.29}]}
        )
        output = StringIO()
        with redirect_stdout(output):
            result = main(["--threshold", "8.3", str(report)])
        self.assertEqual(result, 1)
        self.assertIn("below 8.3", output.getvalue())

    def test_missing_or_invalid_scores_fail_closed(self) -> None:
        for payload in ({"files": []}, {"files": [{}]}, []):
            with self.subTest(payload=payload):
                output = StringIO()
                with redirect_stdout(output):
                    result = main([str(self.write_report(payload))])
                self.assertEqual(result, 2)


if __name__ == "__main__":
    unittest.main()
