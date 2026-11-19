# TracerPyX: Architecture Specification and Implementation Plan

## 1. Executive Summary and System Philosophy

**TracerPyX** is a static vulnerability reachability analyzer for Python applications. Unlike traditional Software Composition Analysis (SCA) tools that only flag dependencies matching affected version ranges, TracerPyX determines whether vulnerable functions, methods, or classes inside dependencies are actually reachable from the application's execution entry points.

The core differentiator of TracerPyX is its **Evidence-Based Vulnerable Symbol Database**:
- Security advisories rarely identify the exact Python symbol that contains the flaw.
- Rather than guessing or naively trusting raw Git diffs or LLM output, TracerPyX analyzes fix commits, extracts AST-level differences, tracks concrete patch evidence, deterministically validates candidate symbols, and records the entire evidence chain in a normalized SQLite database.
- When an application is scanned, the reachability engine queries this database, maps application entry points through a multi-strategy call graph, and issues an evidence-backed classification: **`REACHABLE`**, **`UNREACHABLE`**, or **`UNCERTAIN`**.

---

## 2. System Architecture

TracerPyX is decomposed into two distinct, loosely coupled pipelines that communicate through shared core domain models and a persistent SQLite repository:

```
========================================================================================
                        PIPELINE A: VULNERABILITY INTELLIGENCE
========================================================================================

  [OSV / GHSA Feeds]
         │
         ▼
  ┌───────────────────────┐
  │ 1. Advisory Collector │  Fetches raw JSON advisories, extracts ecosystem, packages,
  └──────────┬────────────┘  affected version ranges, and reference URLs.
             │
             ▼
  ┌───────────────────────┐
  │ 2. Reference Classifier│ Classifies reference URLs (fix commits, PRs, issues, docs)
  └──────────┬────────────┘  and normalizes GitHub/GitLab commit endpoints.
             │
             ▼
  ┌───────────────────────┐
  │ 3. Patch Retriever    │  Fetches unified diffs / patches (cached locally in SQLite).
  └──────────┬────────────┘
             │
             ▼
  ┌───────────────────────┐
  │ 4. AST Patch Analyzer │  Parses unified diffs + Python ASTs of modified files.
  └──────────┬────────────┘  Identifies enclosing functions, methods, classes, and scopes.
             │
             ▼
  ┌───────────────────────┐
  │ 5. Symbol Extractor   │  Generates candidate symbols (deleted/modified lines vs added).
  └──────────┬────────────┘  Optional LLM-assisted candidate suggestion.
             │
             ▼
  ┌───────────────────────┐
  │ 6. Symbol Validator   │  Deterministically validates candidates against AST structure
  └──────────┬────────────┘  and assigns status: CONFIRMED, CANDIDATE, PACKAGE_ONLY,
             │               UNKNOWN, or REJECTED.
             ▼
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │                      PERSISTENT SQLITE DATABASE & REPOSITORY                     │
  │   Advisory  │  AffectedPackage  │  VulnerableSymbol  │  SymbolEvidence  │ Cache   │
  └──────────────────────────────────────────┬───────────────────────────────────────┘
                                             │
=============================================│==========================================
                        PIPELINE B: PROJECT SCANNING & REACHABILITY
=============================================│==========================================
                                             │
  [Target Project Directory]                 │
         │                                   │
         ▼                                   │
  ┌───────────────────────┐                  │
  │ 1. Dependency Scanner │                  │ Reads requirements.txt, pyproject.toml,
  └──────────┬────────────┘                  │ poetry.lock, uv.lock, or virtualenv.
             │                               │
             ▼                               │
  ┌───────────────────────┐                  │
  │ 2. Version Matcher    │◄─────────────────┘ Matches installed versions against
  └──────────┬────────────┘                    advisory ranges; retrieves applicable
             │                                 VulnerableSymbols.
             ▼
  ┌───────────────────────┐
  │ 3. Source AST Parser  │ Extracts facts from application Python source: functions,
  └──────────┬────────────┘ classes, imports, aliases, raw call sites.
             │
             ▼
  ┌───────────────────────┐
  │ 4. Symbol Resolver    │ Resolves local calls, direct/aliased imports, and known
  └──────────┬────────────┘ attributes into Fully Qualified Names (FQNs).
             │
             ▼
  ┌───────────────────────┐
  │ 5. Call Graph Builder │ Constructs directed call graph G = (V, E) with edge metadata
  └──────────┬────────────┘ (resolution kind, location, confidence).
             │
             ▼
  ┌───────────────────────┐
  │ 6. Dynamic Resolver   │ Handles unresolved call sites: constant propagation,
  └──────────┬────────────┘ optional LLM target suggestion, deterministic verification.
             │
             ▼
  ┌───────────────────────┐
  │ 7. Entry Point Engine │ Detects main entry points, CLI scripts, and framework routes
  └──────────┬────────────┘ (Flask, FastAPI, Django) or takes explicit user config.
             │
             ▼
  ┌───────────────────────┐
  │ 8. Reachability Engine│ Path search (BFS/DFS) from Entry Points to Vulnerable Symbols.
  └──────────┬────────────┘ Evaluates unresolved call risks and ambiguity.
             │
             ▼
  ┌───────────────────────┐
  │ 9. Reporter (CLI/JSON)│ Outputs REACHABLE / UNREACHABLE / UNCERTAIN with complete
  └───────────────────────┘ call chains, evidence records, and confidence explanations.
```

---

## 3. Component Responsibilities and Interface Boundaries

### 3.1. Core Domain Layer (`tracerpyx.core`)
Defines shared immutable types, enumerations, domain models, and custom exceptions. **Zero external dependencies.**
- `SymbolValidationStatus`: Enum (`CONFIRMED`, `CANDIDATE`, `PACKAGE_ONLY`, `UNKNOWN`, `REJECTED`).
- `ReachabilityStatus`: Enum (`REACHABLE`, `UNREACHABLE`, `UNCERTAIN`).
- `ConfidenceLevel`: Enum (`HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`).
- `ResolutionKind`: Enum (`DIRECT_IMPORT`, `ALIASED_IMPORT`, `ATTRIBUTE`, `METHOD_DISPATCH`, `DYNAMIC_RESOLVED`, `UNRESOLVED`).
- `VulnerableSymbol`: Target symbol FQN, validation status, confidence, package, and version bounds.
- `SymbolEvidence`: File path, line range, diff hunk, commit SHA, rationale, and extractor method.
- `CallEdge`: Source node, target node, source file, line number, resolution method, confidence.
- `ReachabilityResult`: Vulnerability record, classification, call paths, supporting evidence, limitations.

### 3.2. Advisory & Intelligence Layer (`tracerpyx.intelligence`)
- **`osv_collector.py`**: Queries the OSV API (or local OSV PyPI dumps) for advisories affecting a package or batch of packages.
- **`reference_classifier.py`**: Parses reference URLs using regex/heuristics to classify them into:
  - `FIX_COMMIT` (e.g., `github.com/org/repo/commit/sha`)
  - `PULL_REQUEST` (e.g., `github.com/org/repo/pull/123`)
  - `ISSUE` / `ADVISORY` / `DOCUMENTATION`
- **`patch_retriever.py`**: Retrieves raw `.diff` or `.patch` content given commit or PR references. Integrates caching to prevent duplicate network hits.
- **`ast_patch_analyzer.py`**: Maps patch line numbers to AST nodes. For each changed file:
  - Reconstructs pre-patch and post-patch Python ASTs.
  - Determines which functions, methods, or classes overlap with modified/deleted lines.
- **`symbol_extractor.py`**: Generates `VulnerableSymbol` records. Prioritizes modified/deleted code over newly introduced helper functions.
- **`symbol_validator.py`**: Deterministic verification. Checks whether the candidate symbol exists in the pre-patch AST, checks if the symbol is public or private, and tests naming consistency.

### 3.3. Database & Repository Layer (`tracerpyx.db`)
Manages SQLite persistence with explicit foreign keys, indexes, and versioned migrations.
- **Schema Entities**:
  - `advisories` (id, source, alias_cve, title, details, published_at, modified_at)
  - `affected_packages` (id, advisory_id, package_name, ecosystem, version_range_raw)
  - `vulnerable_symbols` (id, affected_package_id, symbol_name, symbol_type, validation_status, confidence)
  - `symbol_evidence` (id, symbol_id, commit_url, commit_sha, file_path, line_start, line_end, diff_hunk, rationale, extractor)
  - `analysis_cache` (cache_key, cache_type, payload, created_at, expires_at)
  - `schema_migrations` (version, applied_at)
- **Repository Interface**: Clean repository abstraction (`AdvisoryRepository`, `SymbolRepository`, `CacheRepository`) decoupling SQLite from business logic.

### 3.4. Project Discovery & Dependency Layer (`tracerpyx.discovery`)
- **`manifest_parser.py`**: Extracts pinned and ranged dependencies from:
  - `requirements.txt`
  - `pyproject.toml` (PEP 508 / 621)
  - `poetry.lock`
  - `uv.lock` / `Pipfile.lock`
- **`environment_inspector.py`**: Inspects active virtual environments (`sys.path`, `site-packages`) to determine exact installed package versions and paths to library source trees.
- **`version_matcher.py`**: Uses `packaging.version` and `packaging.specifiers` to determine if installed versions fall within advisory affected ranges.

### 3.5. Source Analysis & Call Graph Layer (`tracerpyx.analysis`)
- **`ast_parser.py`**: Safely parses application `.py` files into standard Python ASTs. Attaches line/column spans.
- **`symbol_table.py`**: Maintains scope stacks and registers function definitions, class definitions, and imported symbols per module.
- **`import_resolver.py`**: Resolves `import foo`, `from foo import bar`, and `from foo import bar as baz` to canonical module and symbol targets.
- **`call_extractor.py`**: Walks AST `Call` nodes and extracts caller context, receiver expression, function name, and call site line number.
- **`call_graph.py`**: Directed graph representation supporting nodes (functions/methods) and typed edges (`CallEdge`). Integrates cycle detection.
- **`dynamic_resolver.py`**: Analyzes unresolved call sites using local constant propagation and lexical clues. If an LLM is enabled, accepts suggestions only if validated against real AST symbols.

### 3.6. Reachability Engine (`tracerpyx.engine`)
- **`entry_point_detector.py`**: Identifies:
  - `if __name__ == "__main__":` blocks
  - CLI entry points (functions registered via `argparse`, `click`, `typer`)
  - Framework route handlers (decorated with `@app.get`, `@app.route`, etc.)
  - Explicit entry points supplied by `--entry-point` CLI argument
  - Public functions in library mode
- **`reachability_engine.py`**:
  - Traverses the call graph from all detected entry points to vulnerable symbols.
  - Determines reachability with three-valued logic:
    - **`REACHABLE`**: At least one unbroken, verified path leads from an entry point to the vulnerable symbol.
    - **`UNREACHABLE`**: The vulnerable symbol is known, the package is indexed, the graph has full local coverage, and zero paths exist with zero unresolved dynamic calls that could reach the vulnerable package namespace.
    - **`UNCERTAIN`**: Symbol is `UNKNOWN` or `PACKAGE_ONLY`, OR an unresolved call site exists in a reachable module that imports the affected package, OR coverage is incomplete.
- **`confidence_evaluator.py`**: Calculates path confidence by taking the minimum confidence of all edges in the reachability path and combining it with the symbol validation status.

### 3.7. Reporter Layer (`tracerpyx.reporter`)
- **`terminal_reporter.py`**: Renders clear summary tables, classification badges, and step-by-step visual call path trees with source locations.
- **`json_reporter.py`**: Generates machine-readable, schema-valid JSON for CI/CD integrations.
- **`openvex_reporter.py`**: Emits OpenVEX-compliant JSON-LD documents with `not_affected` justifications (`vulnerable_code_not_in_execute_path`) only when unreachability is strictly established.

---

## 4. Proposed Directory Structure

```
TracerPyX/
├── pyproject.toml
├── README.md
├── docs/
│   ├── implementation_plan.md          # Primary roadmap and technical spec
│   ├── database_schema.md              # SQLite schema specification
│   └── reachability_semantics.md       # Soundness, uncertainty & 3-valued logic
├── src/
│   └── tracerpyx/
│       ├── __init__.py
│       ├── cli.py                      # CLI entry point (argparse / rich)
│       │
│       ├── core/                       # Shared models, types, exceptions
│       │   ├── __init__.py
│       │   ├── models.py               # Domain models (dataclasses / Pydantic)
│       │   ├── enums.py                # Status and confidence enums
│       │   ├── exceptions.py           # Custom exception hierarchy
│       │   └── logging.py              # Centralized logging configuration
│       │
│       ├── db/                         # SQLite persistence layer
│       │   ├── __init__.py
│       │   ├── connection.py           # Connection management & WAL mode
│       │   ├── migrations.py           # Versioned schema migrations
│       │   ├── schema.sql              # Initial DDL statements
│       │   └── repositories/           # Repository pattern implementations
│       │       ├── __init__.py
│       │       ├── advisory_repo.py
│       │       ├── symbol_repo.py
│       │       └── cache_repo.py
│       │
│       ├── intelligence/               # Advisory & patch intelligence pipeline
│       │   ├── __init__.py
│       │   ├── osv_collector.py        # OSV API client with backoff
│       │   ├── reference_classifier.py # URL parser and commit identifier
│       │   ├── patch_retriever.py      # Git diff downloader (cached)
│       │   ├── ast_patch_analyzer.py   # Diff-to-AST mapper
│       │   ├── symbol_extractor.py     # Candidate symbol extraction
│       │   ├── symbol_validator.py     # Deterministic symbol validator
│       │   └── llm/                    # Optional LLM integration
│       │       ├── __init__.py
│       │       ├── base.py             # Provider-independent interface
│       │       ├── prompt_templates.py # Structured reasoning prompts
│       │       └── mock_provider.py    # Deterministic test provider
│       │
│       ├── discovery/                  # Project & dependency discovery
│       │   ├── __init__.py
│       │   ├── project_scanner.py      # Discovers Python files (respects ignores)
│       │   ├── manifest_parser.py      # requirements.txt, pyproject, lockfiles
│       │   ├── environment.py          # Virtualenv & site-packages inspector
│       │   └── version_matcher.py      # PEP 440 version specifier evaluator
│       │
│       ├── analysis/                   # Source parsing & call graph
│       │   ├── __init__.py
│       │   ├── ast_parser.py           # Robust AST parsing with line spans
│       │   ├── symbol_table.py         # Scope and symbol registry
│       │   ├── import_resolver.py      # FQN resolution for imports & aliases
│       │   ├── call_extractor.py       # AST call site visitor
│       │   ├── call_graph.py           # Directed graph G=(V, E)
│       │   └── dynamic_resolver.py     # Unresolved call analysis & heuristic resolution
│       │
│       ├── engine/                     # Central orchestration & reachability
│       │   ├── __init__.py
│       │   ├── entry_point_detector.py # CLI, framework, main detector
│       │   ├── reachability.py         # Cycle-safe graph traversal (BFS/DFS)
│       │   ├── confidence.py           # Path & symbol confidence evaluation
│       │   └── scanner.py              # Main scan controller
│       │
│       └── reporter/                   # Output formatters
│           ├── __init__.py
│           ├── terminal.py             # Console output with visual call paths
│           ├── json_reporter.py        # Machine-readable JSON output
│           └── openvex_reporter.py     # OpenVEX format output
│
└── tests/
    ├── conftest.py                     # Shared fixtures & mock db setup
    ├── unit/
    │   ├── test_core_models.py
    │   ├── test_db_migrations.py
    │   ├── test_osv_collector.py
    │   ├── test_reference_classifier.py
    │   ├── test_ast_patch_analyzer.py
    │   ├── test_symbol_validator.py
    │   ├── test_manifest_parser.py
    │   ├── test_version_matcher.py
    │   ├── test_ast_parser.py
    │   ├── test_symbol_resolver.py
    │   ├── test_call_graph.py
    │   ├── test_entry_point_detector.py
    │   ├── test_reachability.py
    │   └── test_reporters.py
    ├── integration/
    │   ├── test_intelligence_pipeline.py
    │   ├── test_scanner_end_to_end.py
    │   └── test_db_caching.py
    ├── benchmark/
    │   ├── test_symbol_extraction_benchmark.py
    │   └── benchmark_advisories.json   # 10+ manually verified real-world CVEs
    └── fixtures/
        ├── diffs/                      # Real Git diffs for test CVEs
        ├── advisories/                 # Real OSV advisory JSON payloads
        └── test_projects/              # Target sample apps
            ├── reachable_app/
            ├── unreachable_app/
            └── uncertain_app/
```

---

## 5. Detailed Database Schema Design

The SQLite database will use **WAL (Write-Ahead Logging)** mode, foreign key enforcement (`PRAGMA foreign_keys = ON;`), and schema versioning via a `schema_migrations` table.

```sql
-- Migration tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Advisories collected from OSV / GHSA
CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,                 -- e.g. "GHSA-xxxx" or "PYSEC-2024-xxxx"
    source TEXT NOT NULL,                -- "OSV", "GHSA", "PYPA"
    aliases TEXT,                        -- JSON array of CVEs / aliases
    title TEXT,
    details TEXT,
    published_at TIMESTAMP,
    modified_at TIMESTAMP,
    raw_payload TEXT NOT NULL,           -- Complete original JSON for reproducibility
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Affected package version intervals
CREATE TABLE IF NOT EXISTS affected_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    package_name TEXT NOT NULL COLLATE NOCASE,
    ecosystem TEXT NOT NULL,             -- "PyPI"
    version_range_raw TEXT NOT NULL,     -- JSON array of events: introduced, fixed
    FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_affected_pkg_name ON affected_packages(package_name);

-- Advisory references
CREATE TABLE IF NOT EXISTS advisory_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    url TEXT NOT NULL,
    reference_type TEXT NOT NULL,        -- "FIX_COMMIT", "PULL_REQUEST", "ISSUE", "WEB"
    commit_sha TEXT,                     -- Extracted if FIX_COMMIT
    FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_advisory_ref_sha ON advisory_references(commit_sha);

-- Vulnerable symbols extracted from patch analysis
CREATE TABLE IF NOT EXISTS vulnerable_symbols (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    affected_package_id INTEGER NOT NULL,
    symbol_name TEXT NOT NULL,           -- Fully qualified name, e.g. "package.module.func"
    symbol_type TEXT NOT NULL,           -- "FUNCTION", "METHOD", "CLASS", "MODULE"
    validation_status TEXT NOT NULL,     -- "CONFIRMED", "CANDIDATE", "PACKAGE_ONLY", "UNKNOWN", "REJECTED"
    confidence TEXT NOT NULL,            -- "HIGH", "MEDIUM", "LOW", "UNKNOWN"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (affected_package_id) REFERENCES affected_packages(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vuln_symbol_lookup ON vulnerable_symbols(affected_package_id, validation_status);

-- Supporting evidence linking a symbol to concrete patch changes
CREATE TABLE IF NOT EXISTS symbol_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    symbol_id INTEGER NOT NULL,
    commit_url TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    diff_hunk TEXT,
    rationale TEXT NOT NULL,
    extractor TEXT NOT NULL,             -- "AST_DIFF", "EXPLICIT_ADVISORY", "LLM_VALIDATED"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (symbol_id) REFERENCES vulnerable_symbols(id) ON DELETE CASCADE
);

-- Analysis cache for diffs, AST parsing, and network responses
CREATE TABLE IF NOT EXISTS analysis_cache (
    cache_key TEXT PRIMARY KEY,          -- Hash of input URL / content
    cache_type TEXT NOT NULL,            -- "RAW_DIFF", "OSV_QUERY", "AST_FACTS"
    payload TEXT NOT NULL,               -- Cached string or JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP                -- Optional TTL
);
```

---

## 6. Rules for Evidence and Validation

TracerPyX establishes strict epistemological rules to prevent false certainties:

### 6.1. Symbol Status Criteria
1. **`CONFIRMED`**:
   - The symbol was identified directly in an advisory security bulletin, OR
   - The symbol is mapped to deleted or modified logic in a verified fix commit **AND** has been validated against the pre-patch AST of the affected package version.
2. **`CANDIDATE`**:
   - The symbol was modified in a fix commit, but the target package version's AST has not been verified, OR
   - The symbol was suggested by heuristic diff scoring or an LLM and verified to exist syntactically, but multiple candidate functions were modified in the same commit.
3. **`PACKAGE_ONLY`**:
   - The advisory version range is confirmed affected, but no fix commit exists, or the fix commit only altered non-Python files (e.g., C extensions, configuration, documentation).
4. **`UNKNOWN`**:
   - The advisory has contradictory, ambiguous, or unparseable references.
5. **`REJECTED`**:
   - The symbol was suggested (e.g. by an LLM or keyword match) but was determined to be a newly added function (the fix itself), a test fixture, or does not exist in the vulnerable codebase.

### 6.2. Reachability Classification Invariants
- An advisory with `PACKAGE_ONLY` or `UNKNOWN` symbols whose package is imported or called by the application must **always** yield **`UNCERTAIN`**, never `UNREACHABLE`.
- If an application calls a library through an unresolved dynamic dispatch (e.g., `getattr()`, `dispatcher[event]()`), and that module imports the affected package, the reachability engine must downgrade a potential `UNREACHABLE` to **`UNCERTAIN`**.
- An advisory may only be declared **`UNREACHABLE`** when:
  1. All applicable vulnerable symbols are identified (`CONFIRMED` or `CANDIDATE`).
  2. Complete call graph traversal from all entry points establishes zero paths to the symbols.
  3. No unresolvable dynamic call sites exist in reachable application modules that import the vulnerable package.

---

## 7. Stage-by-Stage Implementation Plan

We organize implementation into **14 discrete stages**. Each stage is self-contained, fully testable with unit tests, and accompanied by explicit acceptance criteria.

```
Stage 1: Project Foundation & CLI
   │
   ▼
Stage 2: Core Models & Enums
   │
   ▼
Stage 3: SQLite Database, Migrations & Repositories
   │
   ▼
Stage 4: Advisory Models & OSV Data Ingestion
   │
   ▼
Stage 5: Reference Classification & Commit Discovery
   │
   ▼
Stage 6: Patch Retrieval & Caching
   │
   ▼
Stage 7: AST Patch Analysis & Candidate Symbol Extraction
   │
   ▼
Stage 8: Deterministic Symbol Validation
   │
   ▼
Stage 9: Optional Provider-Independent LLM Integration
   │
   ▼
Stage 10: Dependency Inventory & Version Matching
   │
   ▼
Stage 11: Python Source Analysis & Call Graph Construction
   │
   ▼
Stage 12: Entry-Point Detection & Reachability Analysis
   │
   ▼
Stage 13: Dynamic-Call Handling & Conservative Fallbacks
   │
   ▼
Stage 14: Reporters, End-to-End Integration & Real-World CVE Benchmark
```

### Stage 1: Project Foundation, Package Structure, and CLI
- **Objective**: Establish the repository layout, packaging configuration, centralized logging, and base CLI skeleton.
- **Deliverables**:
  - `pyproject.toml` with dependencies (`packaging`, `requests`, `rich`, `pytest`).
  - `src/tracerpyx/` namespace package setup.
  - `src/tracerpyx/core/logging.py` with structured, configurable logging.
  - `src/tracerpyx/cli.py` with subcommand parsing (`db`, `scan`, `advisory`, `version`).
- **Tests**: CLI invocation, argument parsing, log level verification.
- **Acceptance Criteria**: Running `tracerpyx --help` succeeds; tests pass under `pytest`.

### Stage 2: Core Domain Models & Enums
- **Objective**: Define all shared immutable data structures, status enums, and custom exceptions.
- **Deliverables**:
  - `src/tracerpyx/core/enums.py`: `SymbolValidationStatus`, `ReachabilityStatus`, `ConfidenceLevel`, etc.
  - `src/tracerpyx/core/models.py`: Dataclasses for `Advisory`, `VulnerableSymbol`, `SymbolEvidence`, `CallEdge`, `ScanResult`.
  - `src/tracerpyx/core/exceptions.py`: TracerPyX base exception tree.
- **Tests**: Model instantiation, serialization/deserialization, immutability, validation constraints.
- **Acceptance Criteria**: Models represent the full domain; 100% test coverage for core types.

### Stage 3: SQLite Database, Schema, Migrations, and Repositories
- **Objective**: Build the persistent relational storage engine with versioned migrations and clean repository access.
- **Deliverables**:
  - `src/tracerpyx/db/schema.sql`: Full DDL with constraints and indexes.
  - `src/tracerpyx/db/connection.py`: SQLite connection manager with WAL mode and foreign keys enabled.
  - `src/tracerpyx/db/migrations.py`: Schema version runner.
  - `src/tracerpyx/db/repositories/`: `AdvisoryRepository`, `SymbolRepository`, `CacheRepository`.
- **Tests**: In-memory and file-based SQLite tests, migration application, foreign key cascade enforcement, repository CRUD operations.
- **Acceptance Criteria**: All tables created cleanly; transactions roll back on error; repository queries verified.

### Stage 4: Advisory Models & OSV Data Ingestion
- **Objective**: Ingest vulnerability advisories from the OSV API and store normalized records in SQLite.
- **Deliverables**:
  - `src/tracerpyx/intelligence/osv_collector.py`: OSV REST client with retries and timeout handling.
  - Ingestion pipeline parsing OSV JSON (ID, aliases, affected version ranges, references).
  - Storage into `advisories` and `affected_packages` tables via repositories.
- **Tests**: Mock OSV HTTP responses (success, error, 404, rate limit); normalization of varied OSV schemas.
- **Acceptance Criteria**: Given a package name, fetches and persists real/mock advisories without network leakage during tests.

### Stage 5: Reference Classification & Commit Discovery
- **Objective**: Parse advisory reference URLs and classify them into fix commits, pull requests, issues, or documentation.
- **Deliverables**:
  - `src/tracerpyx/intelligence/reference_classifier.py`: Regex and heuristic parser supporting GitHub, GitLab, and standard Git web viewers.
  - Extracts commit SHAs and repository identifiers.
  - Persists classified references into `advisory_references`.
- **Tests**: Benchmark of 50+ diverse reference URL formats (commit links, PR diff links, commit comparisons, issue trackers).
- **Acceptance Criteria**: Correctly identifies fix commit SHAs across all test URL patterns; ignores non-code links.

### Stage 6: Patch Retrieval & Caching
- **Objective**: Retrieve raw unified diffs for identified fix commits and cache them in SQLite.
- **Deliverables**:
  - `src/tracerpyx/intelligence/patch_retriever.py`: Downloads patch/diff content (e.g. `https://github.com/org/repo/commit/{sha}.patch`).
  - Integration with `analysis_cache` table to avoid redundant network downloads.
- **Tests**: Mock diff downloads, caching hit/miss verification, handling deleted repositories or private commits.
- **Acceptance Criteria**: Fetched diffs are saved to cache; subsequent requests resolve from SQLite without network activity.

### Stage 7: AST Patch Analysis & Candidate Symbol Extraction
- **Objective**: Parse unified diffs and map modified line ranges to Python AST symbols (functions, methods, classes).
- **Deliverables**:
  - `src/tracerpyx/intelligence/ast_patch_analyzer.py`: Unified diff parser detecting modified files, line ranges, and added/deleted lines.
  - Python AST visitor mapping diff line ranges to enclosing scopes.
  - `src/tracerpyx/intelligence/symbol_extractor.py`: Extracts candidate vulnerable symbols. Distinguishes modified existing logic from newly added functions.
- **Tests**: Tested on real Git diffs with varied structures (renamed functions, modified methods inside nested classes, top-level functions, docstring-only changes).
- **Acceptance Criteria**: Accurately extracts the target function name and line span from test diffs.

### Stage 8: Deterministic Symbol Validation
- **Objective**: Filter and validate candidate symbols deterministically to assign evidence-backed validation statuses.
- **Deliverables**:
  - `src/tracerpyx/intelligence/symbol_validator.py`:
    - Checks candidate existence against pre-patch code.
    - Filters out test files (`test_*.py`), setup scripts (`setup.py`), and documentation.
    - Assigns `CONFIRMED`, `CANDIDATE`, `PACKAGE_ONLY`, or `REJECTED`.
    - Persists results to `vulnerable_symbols` and `symbol_evidence` tables.
- **Tests**: Validation unit tests covering false-positive candidates, newly added helper functions, and confirmed functions.
- **Acceptance Criteria**: Correctly classifies confirmed vs rejected candidate symbols with explicit rationales.

### Stage 9: Optional Provider-Independent LLM Integration
- **Objective**: Provide an optional interface for LLM-assisted candidate suggestion, strictly subject to deterministic validation.
- **Deliverables**:
  - `src/tracerpyx/intelligence/llm/base.py`: Abstract `LLMProvider` interface.
  - `src/tracerpyx/intelligence/llm/prompt_templates.py`: Structured prompt asking for JSON response with candidate symbol and reason.
  - `src/tracerpyx/intelligence/llm/mock_provider.py`: Deterministic mock provider for tests.
  - Pipeline hook: LLM suggestions are treated strictly as unverified candidates and routed through `symbol_validator.py`.
- **Tests**: Mock LLM responses (well-formed, malformed, hallucinated function names); verifying that hallucinated symbols are rejected.
- **Acceptance Criteria**: LLM cannot elevate a symbol to `CONFIRMED` without deterministic AST validation.

### Stage 10: Dependency Inventory & Version Matching
- **Objective**: Discover project dependencies and match installed/locked versions against affected advisory ranges.
- **Deliverables**:
  - `src/tracerpyx/discovery/project_scanner.py`: Finds project manifests while ignoring `.venv`, `.git`, `node_modules`, etc.
  - `src/tracerpyx/discovery/manifest_parser.py`: Parses `requirements.txt` and `pyproject.toml`.
  - `src/tracerpyx/discovery/environment.py`: Inspects active environment / `site-packages`.
  - `src/tracerpyx/discovery/version_matcher.py`: PEP 440 version specifier evaluation.
- **Tests**: Parsing various manifest formats, complex version specifiers (`>=1.2.0,<1.5.1`, `~=2.1`, `!=1.3.0`), pre-releases.
- **Acceptance Criteria**: Accurately identifies which installed packages have active advisories in the database.

### Stage 11: Python Source Analysis & Call Graph Construction
- **Objective**: Parse application Python files into ASTs, resolve imports/symbols, and construct the directed call graph.
- **Deliverables**:
  - `src/tracerpyx/analysis/ast_parser.py`: AST extraction with exact line/column tracking.
  - `src/tracerpyx/analysis/symbol_table.py`: Module and scope symbol registry.
  - `src/tracerpyx/analysis/import_resolver.py`: Resolves direct and aliased imports to FQNs.
  - `src/tracerpyx/analysis/call_extractor.py`: Extracts raw call sites.
  - `src/tracerpyx/analysis/call_graph.py`: Directed graph `CallGraph` with edge metadata (resolution method, file, line, confidence).
- **Tests**: Multi-file call resolution, aliased imports (`import foo as bar`), intra-module calls, method calls, recursion/cycles.
- **Acceptance Criteria**: Correctly builds call graph connecting callers to callees across multiple files with cycle safety.

### Stage 12: Entry-Point Detection & Reachability Analysis
- **Objective**: Automatically detect execution entry points and perform graph reachability analysis to vulnerable symbols.
- **Deliverables**:
  - `src/tracerpyx/engine/entry_point_detector.py`: Detects `main` blocks, CLI commands, web route handlers, or manual entries.
  - `src/tracerpyx/engine/reachability.py`: Graph traversal (BFS/DFS) searching for paths from entry points to `VulnerableSymbol` targets.
  - `src/tracerpyx/engine/confidence.py`: Evaluates composite path and evidence confidence.
- **Tests**: Reachable path detection, unreachable path verification, multi-entry-point graphs, cycle handling.
- **Acceptance Criteria**: Returns `REACHABLE` with call chain when path exists; returns `UNREACHABLE` when completely disjoint.

### Stage 13: Dynamic-Call Handling & Conservative Fallbacks
- **Objective**: Account for unresolved dynamic calls, reflection, and missing metadata without compromising soundness.
- **Deliverables**:
  - `src/tracerpyx/analysis/dynamic_resolver.py`: Detects unresolved call sites (`getattr`, callbacks, dynamic dispatch). Attempts constant propagation.
  - Integration with reachability engine: If an unresolved call exists in a reachable module that imports the affected package, downgrade verdict to `UNCERTAIN`.
- **Tests**: Dynamic dispatch scenarios, constant propagation success cases, conservative uncertainty fallback cases.
- **Acceptance Criteria**: Unresolved dynamic calls properly trigger `UNCERTAIN` classification with explicit justification.

### Stage 14: Reporters, End-to-End Integration & Real-World CVE Benchmark
- **Objective**: Finalize CLI, terminal/JSON/OpenVEX reporting, end-to-end integration tests, and a benchmark of 10+ real-world Python CVEs.
- **Deliverables**:
  - `src/tracerpyx/reporter/terminal.py`: Rich visual console output with call path trees.
  - `src/tracerpyx/reporter/json_reporter.py`: Machine-readable JSON output.
  - `src/tracerpyx/reporter/openvex_reporter.py`: OpenVEX format emission.
  - Benchmark test suite with 10+ real-world Python CVEs (e.g., in `requests`, `flask`, `urllib3`, `jinja2`).
- **Tests**: End-to-end CLI runs on sample projects, schema validation of JSON and OpenVEX outputs, benchmark accuracy checks.
- **Acceptance Criteria**: Full scan execution from CLI; all benchmark tests pass; OpenVEX output passes standard schema validation.

---

## 8. Technical Risks and Mitigations

| Risk | Impact | Architectural Mitigation |
|------|--------|--------------------------|
| **Advisories without Fix Commits** | High | Classify as `PACKAGE_ONLY`. The engine will check package-level reachability and issue `UNCERTAIN` with clear guidance instead of crashing or hallucinating a symbol. |
| **Monolithic/Diff Noise (Commits touching 50+ files)** | Medium | The AST patch analyzer strictly ignores non-Python files, test suites, and documentation. Diff hunks are scored by proximity to deleted executable lines. |
| **Virtual Environment Bloat** | High | Lazy dependency indexing: TracerPyX only parses the source files of third-party dependencies that match an active, affected advisory in the project. |
| **Python Dynamic Metaprogramming** | High | Three-valued logic: Never declare a package `UNREACHABLE` if reachable code contains unresolvable dynamic dispatches into that package's namespace. |
| **Flaky External Network Calls** | High | All network calls (OSV API, Git patches) pass through the SQLite caching layer. Unit and integration tests run entirely against local mocks and fixtures. |

---

## 9. Next Steps

Upon your approval of this plan, we will proceed to **Stage 1**:
- Set up `pyproject.toml`, directory structure, base CLI, and centralized logging.
- Add unit tests for the CLI and logger.
- Verify tests pass cleanly under `pytest`.
