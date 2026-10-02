#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: build-docs-package.sh --version <semver> --output-dir <dir>
EOF
}

version=""
output_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${version}" || -z "${output_dir}" ]]; then
  usage >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${output_dir}" != /* ]]; then
  output_dir="${repo_root}/${output_dir}"
fi
package_name="rust-gvm-api-docs-${version}"
staging_root="${repo_root}/dist/docs-package"
package_root="${staging_root}/${package_name}"
source_openapi_version="$(
  awk '/^info:$/ { in_info = 1; next }
       in_info && /^  version:/ { gsub(/"/, "", $2); print $2; exit }' \
    "${repo_root}/spec/rest-api/openapi.yaml"
)"

if [[ -z "${source_openapi_version}" || "${source_openapi_version}" != "${version}" ]]; then
  echo "OpenAPI info.version '${source_openapi_version:-missing}' does not match package version '${version}'" >&2
  exit 1
fi

rm -rf "${package_root}"
mkdir -p "${package_root}/api/rest" "${package_root}/examples"
mkdir -p "${output_dir}"

cp "${repo_root}/docs/user/index.md" "${package_root}/README.md"
cp "${repo_root}/docs/user/usage.md" "${package_root}/usage.md"
cp "${repo_root}/docs/user/api-reference.md" "${package_root}/api-reference.md"
cp "${repo_root}/docs/user/examples.md" "${package_root}/examples.md"
cp "${repo_root}/docs/user/migration.md" "${package_root}/migration.md"
cp -R "${repo_root}/docs/user/examples/." "${package_root}/examples/"
cp "${repo_root}/packaging/gvm-gateway.toml" "${package_root}/package-config.example.toml"
cp "${repo_root}/packaging/gvm-gateway.container.toml" "${package_root}/container-config.example.toml"
find "${repo_root}/spec/rest-api" -maxdepth 1 -type f -name '*.yaml' -exec cp {} "${package_root}/api/rest/" \;

cat > "${package_root}/VERSION" <<EOF
${version}
EOF

archive_path="${output_dir}/${package_name}.tar.gz"
(
  cd "${staging_root}"
  tar czf "${archive_path}" "${package_name}"
)
sha256sum "${archive_path}" > "${archive_path}.sha256"
