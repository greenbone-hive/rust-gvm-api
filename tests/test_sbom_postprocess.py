"""Contract tests for deterministic CycloneDX metadata enrichment."""

import json
import tempfile
import unittest
from pathlib import Path

from scripts.sbom_postprocess import (
    CC0_LICENSE,
    BUILD_LIFECYCLE,
    declare_complete,
    main,
    normalize_spec_version,
    transform,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "sbom" / "minimal.cdx.json"


class SbomPostprocessTests(unittest.TestCase):
    def test_enrichment_adds_quality_metadata_without_hiding_dependencies(self) -> None:
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        transformed = transform(document, ROOT / "Cargo.toml", True)
        metadata = transformed["metadata"]

        self.assertEqual(transformed["specVersion"], "1.5")
        self.assertIn(CC0_LICENSE, metadata["licenses"])
        self.assertIn(BUILD_LIFECYCLE, metadata["lifecycles"])
        self.assertEqual(metadata["supplier"], {"name": "greenbone-hive"})
        self.assertEqual(
            metadata["component"]["externalReferences"],
            [{"type": "vcs", "url": "https://github.com/greenbone-hive/rust-gvm-api"}],
        )
        self.assertEqual(transformed["components"][0]["supplier"], {"name": "crates.io"})
        self.assertEqual(transformed["compositions"][0]["aggregate"], "complete")

    def test_invalid_versions_and_compositions_fail_or_normalize(self) -> None:
        self.assertEqual(normalize_spec_version(None), "1.5")
        self.assertEqual(normalize_spec_version("1.6"), "1.6")
        with self.assertRaisesRegex(ValueError, "compositions"):
            declare_complete(
                {
                    "dependencies": [{"ref": "a", "dependsOn": []}],
                    "compositions": {},
                }
            )

    def test_cli_rewrites_the_document(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="sbom-postprocess-")
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "input.cdx.json"
        path.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
        result = main(
            [
                "--cargo-toml",
                str(ROOT / "Cargo.toml"),
                "--declare-dependency-complete",
                str(path),
            ]
        )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(path.read_text())["specVersion"], "1.5")


if __name__ == "__main__":
    unittest.main()
