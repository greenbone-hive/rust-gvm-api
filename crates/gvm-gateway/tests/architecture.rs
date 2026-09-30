// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Architectural boundary tests.
//!
//! These tests enforce that the domain, application, and REST adapter crates
//! do **not** depend on GMP/GVMD protocol crates.  Only the outgoing gvmd
//! adapter (`gvm-gateway-gvmd`) and the composition-root binary
//! (`gvm-gateway`) are allowed to reference `gvm-gmp`, `gvm-client`, or
//! `gvm-connection`.

use std::path::{Path, PathBuf};

/// GMP/GVMD protocol crates that must NOT appear in inner-layer
/// `[dependencies]` sections.
const BANNED_DEPS: &[&str] = &["gvm-gmp", "gvm-client", "gvm-connection"];

/// Crates that form the inner layers of the hexagonal architecture.
const INNER_CRATES: &[(&str, &str)] = &[
    ("gvm-gateway-domain", "crates/gvm-gateway-domain/Cargo.toml"),
    ("gvm-gateway-app", "crates/gvm-gateway-app/Cargo.toml"),
    ("gvm-gateway-rest", "crates/gvm-gateway-rest/Cargo.toml"),
];

/// Asserts that inner-layer crates do not list any GMP protocol crate as a
/// runtime dependency.  Dev-dependencies are allowed (e.g. for integration
/// tests that spin up a mock server).
#[test]
fn inner_crates_must_not_depend_on_gmp_protocol_crates() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let mut violations = Vec::new();

    for &(crate_name, cargo_toml_path) in INNER_CRATES {
        let full_path = workspace_root.join(cargo_toml_path);
        let content = std::fs::read_to_string(&full_path).unwrap_or_else(|err| {
            panic!("failed to read {}: {err}", full_path.display());
        });

        // Extract only the [dependencies] section (not [dev-dependencies] or
        // [build-dependencies]).  We look for lines between `[dependencies]`
        // and the next `[` header.
        let deps_section = extract_dependencies_section(&content);

        for banned in BANNED_DEPS {
            // Check for the dependency as a TOML key (at the start of a line
            // or as a dotted key like `gvm-gmp.workspace`).
            let patterns = [
                format!("\n{banned}"),
                format!("{banned}."),
                format!("{banned} "),
                format!("{banned}="),
            ];
            let found = deps_section
                .as_ref()
                .map(|section| patterns.iter().any(|p| section.contains(p.as_str())))
                .unwrap_or(false);

            if found {
                violations.push(format!(
                    "{crate_name} depends on `{banned}` (in {cargo_toml_path})"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Architectural boundary violations detected:\n  - {}",
        violations.join("\n  - ")
    );
}

/// Inner production source must exchange domain models only; fully qualified
/// GMP, client, connection, protocol, or XML parser types cannot cross the
/// outgoing-adapter boundary even through an undeclared or transitive path.
#[test]
fn inner_crates_must_not_reference_raw_gmp_or_xml_types() {
    let root = workspace_root();
    let mut violations = Vec::new();
    let forbidden = [
        "gvm_gmp::",
        "gvm_client::",
        "gvm_connection::",
        "gvm_protocol::",
        "quick_xml::",
        "roxmltree::",
        "xmltree::",
        "serde_xml_rs::",
    ];

    for (crate_name, manifest_path) in INNER_CRATES {
        let crate_dir = root
            .join(manifest_path)
            .parent()
            .expect("inner crate manifest has a parent")
            .join("src");
        for file in production_rust_files(&crate_dir) {
            let contents = std::fs::read_to_string(&file)
                .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
            for marker in forbidden {
                if contents.contains(marker) {
                    violations.push(format!(
                        "{crate_name}: {} references {marker}",
                        file.strip_prefix(&root).unwrap_or(&file).display()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "raw GMP/XML types crossed the domain/application/REST boundary:\n  - {}",
        violations.join("\n  - ")
    );
}

/// Extracts the `[dependencies]` section from a Cargo.toml string.
/// Returns the text between `[dependencies]` and the next section header.
fn extract_dependencies_section(content: &str) -> Option<String> {
    let mut in_deps = false;
    let mut section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[dependencies]" {
            in_deps = true;
            continue;
        }
        if in_deps {
            if trimmed.starts_with('[') {
                break;
            }
            section.push('\n');
            section.push_str(line);
        }
    }

    if section.is_empty() {
        None
    } else {
        Some(section)
    }
}

/// Unit tests must live in sidecar `*_test.rs` files, while integration and
/// other higher-level tests stay under `tests/` directories.
#[test]
fn unit_tests_must_use_sidecar_test_files() {
    let workspace_root = workspace_root();
    let mut violations = Vec::new();

    for rust_file in production_rust_files(&workspace_root.join("crates")) {
        let relative_path = rust_file
            .strip_prefix(&workspace_root)
            .unwrap_or(&rust_file)
            .display()
            .to_string();

        if rust_file.file_name().is_some_and(|name| name == "tests.rs") {
            violations.push(format!(
                "{relative_path}: unit-test sidecars must be named `*_test.rs`"
            ));
        }

        let content = std::fs::read_to_string(&rust_file).unwrap_or_else(|err| {
            panic!("failed to read {}: {err}", rust_file.display());
        });

        if let Some(line_number) = first_inline_cfg_test_module_line(&content) {
            violations.push(format!(
                "{relative_path}:{line_number}: move inline `#[cfg(test)] mod ... {{ ... }}` into a `*_test.rs` sidecar"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Test-layout violations detected:\n  - {}",
        violations.join("\n  - ")
    );
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn production_rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_production_rust_files(root, &mut files);
    files.sort();
    files
}

fn collect_production_rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(path).unwrap_or_else(|err| {
        panic!("failed to read directory {}: {err}", path.display());
    });

    for entry in entries {
        let entry = entry.unwrap_or_else(|err| {
            panic!(
                "failed to read directory entry in {}: {err}",
                path.display()
            );
        });
        let path = entry.path();
        let file_type = entry.file_type().unwrap_or_else(|err| {
            panic!("failed to read file type for {}: {err}", path.display());
        });

        if file_type.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| matches!(name.to_str(), Some("target" | ".git" | "tests")))
            {
                continue;
            }
            collect_production_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn first_inline_cfg_test_module_line(content: &str) -> Option<usize> {
    let lines: Vec<_> = content.lines().collect();

    for (index, line) in lines.iter().enumerate() {
        if line.trim() != "#[cfg(test)]" {
            continue;
        }

        for candidate in lines.iter().skip(index + 1) {
            let trimmed = candidate.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#[") {
                continue;
            }

            if trimmed.starts_with("mod ") && trimmed.ends_with('{') {
                return Some(index + 1);
            }
            break;
        }
    }

    None
}
