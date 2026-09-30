"""Ensure every first-party workspace member stays in security evidence."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.check_workspace_unsafe import first_party_unsafe, unsafe_total
from scripts.workspace_inventory import (
    WorkspacePackage,
    load_inventory,
    validate_inventory,
)


ROOT = Path(__file__).resolve().parents[1]


class WorkspaceSecurityTests(unittest.TestCase):
    def test_committed_inventory_matches_locked_cargo_metadata(self) -> None:
        metadata = json.loads(
            subprocess.run(
                [
                    "cargo",
                    "metadata",
                    "--locked",
                    "--no-deps",
                    "--format-version",
                    "1",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            .stdout
        )
        validate_inventory(
            load_inventory(ROOT / "supply-chain" / "workspace-packages.toml"),
            metadata,
            ROOT,
        )

    def test_new_workspace_member_cannot_escape_inventory(self) -> None:
        inventory = (WorkspacePackage("one", Path("one/Cargo.toml")),)
        metadata = {
            "workspace_members": ["one-id", "two-id"],
            "packages": [
                {
                    "id": "one-id",
                    "name": "one",
                    "manifest_path": str(ROOT / "one/Cargo.toml"),
                },
                {
                    "id": "two-id",
                    "name": "two",
                    "manifest_path": str(ROOT / "two/Cargo.toml"),
                },
            ],
        }
        with self.assertRaisesRegex(ValueError, "missing: two"):
            validate_inventory(inventory, metadata, ROOT)

    def test_unsafe_counter_targets_only_named_first_party_package(self) -> None:
        package = WorkspacePackage("gateway", Path("gateway/Cargo.toml"))
        payload = {
            "packages": [
                {
                    "package": {"id": {"name": "dependency"}},
                    "unsafety": {"used": {"functions": {"unsafe_": 99}}},
                },
                {
                    "package": {"id": {"name": "gateway"}},
                    "unsafety": {
                        "used": {
                            "functions": {"unsafe_": 1},
                            "expressions": {"unsafe_": 2},
                        }
                    },
                },
            ]
        }
        self.assertEqual(first_party_unsafe(payload, package), 3)
        self.assertEqual(unsafe_total({"functions": {"unsafe_": 0}}), 0)

    def test_inventory_rejects_parent_paths(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="workspace-inventory-")
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "inventory.toml"
        path.write_text(
            'schema = 1\n[[packages]]\nname = "bad"\nmanifest = "../Cargo.toml"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "unsafe manifest"):
            load_inventory(path)


if __name__ == "__main__":
    unittest.main()
