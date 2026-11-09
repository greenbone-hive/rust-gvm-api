"""Regression coverage for inventory-scoped release SBOM collection."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.collect_workspace_sboms import collect
from scripts.workspace_inventory import WorkspacePackage


class CollectWorkspaceSbomsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="workspace-sbom-collector-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.package = WorkspacePackage("gateway", Path("crates/gateway/Cargo.toml"))
        self.package_dir = self.root / self.package.manifest.parent
        self.package_dir.mkdir(parents=True)

    def test_only_inventory_documents_are_collected_for_release_formats(self) -> None:
        # A repository fixture may look like a CycloneDX document but must never
        # enter release evidence when it is not owned by a workspace package.
        for document_format in ("json", "xml"):
            (self.package_dir / f"gateway.cdx.{document_format}").write_text(
                document_format,
                encoding="utf-8",
            )
        fixture = self.root / "tests" / "fixtures" / "minimal.cdx.json"
        fixture.parent.mkdir(parents=True)
        fixture.write_text("fixture", encoding="utf-8")
        destination = self.root / "collected"

        with (
            patch("scripts.collect_workspace_sboms.ROOT", self.root),
            patch(
                "scripts.collect_workspace_sboms.validated_inventory",
                return_value=(self.package,),
            ),
        ):
            collected = collect(destination, ("json", "xml"))

        self.assertEqual(
            [path.name for path in collected],
            ["gateway.cdx.json", "gateway.cdx.xml"],
        )
        self.assertEqual(
            sorted(path.name for path in destination.iterdir()),
            ["gateway.cdx.json", "gateway.cdx.xml"],
        )

    def test_missing_inventory_document_fails_closed(self) -> None:
        # A partial JSON/XML set is not valid release evidence and must stop the
        # workflow instead of producing an incomplete archive.
        (self.package_dir / "gateway.cdx.json").write_text("json", encoding="utf-8")

        with (
            patch("scripts.collect_workspace_sboms.ROOT", self.root),
            patch(
                "scripts.collect_workspace_sboms.validated_inventory",
                return_value=(self.package,),
            ),
            self.assertRaisesRegex(ValueError, "expected one XML SBOM"),
        ):
            collect(self.root / "collected", ("json", "xml"))


if __name__ == "__main__":
    unittest.main()
