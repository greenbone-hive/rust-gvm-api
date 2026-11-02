name: gvm-gateway
arch: __ARCH__
platform: linux
version: __VERSION__
release: "__RELEASE__"
section: net
priority: optional
maintainer: clawosiris <clawosiris@users.noreply.github.com>
description: |
  REST gateway for Greenbone Vulnerability Management.
vendor: clawosiris
homepage: https://github.com/greenbone-hive/rust-gvm-api
license: AGPL-3.0-or-later
contents:
  - src: ./dist/package-root/usr/bin/gvm-gateway
    dst: /usr/bin/gvm-gateway
  - dst: /etc/gvm-gateway
    type: dir
  - src: ./dist/package-root/etc/gvm-gateway/gvm-gateway.toml.example
    dst: /etc/gvm-gateway/gvm-gateway.toml.example
    type: config|noreplace
  - src: ./dist/package-root/usr/share/doc/gvm-gateway/README.md
    dst: /usr/share/doc/gvm-gateway/README.md
  - src: ./dist/package-root/usr/share/doc/gvm-gateway/BUILDINFO
    dst: /usr/share/doc/gvm-gateway/BUILDINFO
  - src: ./dist/package-root/usr/share/licenses/gvm-gateway/LICENSE
    dst: /usr/share/licenses/gvm-gateway/LICENSE
overrides:
  deb:
    depends:
      - libc6
  archlinux:
    depends:
      - glibc
