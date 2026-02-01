# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-02-01

### Added
- **Plugin Architecture**: Capability-based plugin system for secure extensions (EXT-001, EXT-002).
- **Parallel Scanning**: Scanner now uses `ThreadPoolExecutor` for concurrent rule processing (PERF-002).
- **Performance**: Rule caching to minimize disk I/O (PERF-001).
- **Resource Management**: HTTP client connection pool eviction for LLM client (PERF-003).

### Changed
- **Scanner**: Updated `Scanner.scan_all` to support multi-threaded execution.
- **Dependencies**: Added `concurrent.futures` usage (standard library) and updated `vulnguard/pkg/advisor/llm_client.py` for better resource handling.

### Fixed
- Fixed potential memory leak in LLM HTTP client pool.
