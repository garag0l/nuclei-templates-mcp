# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-11-21

### Added
- Composite **GitHub Action** (`action.yml`): scan an MCP server with
  `uses: garag0l/nuclei-templates-mcp@v0.1.1`. It installs nuclei (pinned,
  checksum-verified), runs the bundled templates against `target`, and supports
  a `validate` mode. Inputs are passed through env vars (no template injection),
  and an end-to-end CI job validates the templates and scans the vulnerable mock
  server through the action, asserting the 5 expected matches.

## [0.1.0] - 2026-11-21

### Added
- 6 detection templates: unauthenticated Streamable HTTP server, tools listed without auth (stateful and stateless servers), cross-site `text/plain` JSON-RPC (CVE-2026-33252 behavior), Host header not validated (DNS rebinding), legacy SSE transport without auth, RFC 9728 OAuth protected resource metadata.
- Mock MCP server with vulnerable / stateless / hardened modes and an exact-match CI harness.
