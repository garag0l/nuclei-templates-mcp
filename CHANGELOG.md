# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-21

### Added
- 6 detection templates: unauthenticated Streamable HTTP server, tools listed without auth (stateful and stateless servers), cross-site `text/plain` JSON-RPC (CVE-2026-33252 behavior), Host header not validated (DNS rebinding), legacy SSE transport without auth, RFC 9728 OAuth protected resource metadata.
- Mock MCP server with vulnerable / stateless / hardened modes and an exact-match CI harness.
