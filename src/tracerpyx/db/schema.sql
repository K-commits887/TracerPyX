-- TracerPyX Migration 001: Initial Schema
-- Migration-Version: 1
-- Migration-Name: initial_schema

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    aliases TEXT,
    title TEXT,
    details TEXT,
    published_at TEXT,
    modified_at TEXT,
    raw_payload TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS affected_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    package_name TEXT NOT NULL COLLATE NOCASE,
    ecosystem TEXT NOT NULL DEFAULT 'PyPI',
    version_range_raw TEXT NOT NULL,
    FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_affected_pkg_name ON affected_packages(package_name);

CREATE TABLE IF NOT EXISTS advisory_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    advisory_id TEXT NOT NULL,
    url TEXT NOT NULL,
    reference_type TEXT NOT NULL,
    commit_sha TEXT,
    FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_advisory_ref_sha ON advisory_references(commit_sha);

CREATE TABLE IF NOT EXISTS vulnerable_symbols (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    affected_package_id INTEGER NOT NULL,
    symbol_name TEXT NOT NULL,
    symbol_type TEXT NOT NULL DEFAULT 'FUNCTION',
    validation_status TEXT NOT NULL,
    confidence TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (affected_package_id) REFERENCES affected_packages(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vuln_symbol_lookup ON vulnerable_symbols(affected_package_id, validation_status);

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
    extractor TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (symbol_id) REFERENCES vulnerable_symbols(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analysis_cache (
    cache_key TEXT PRIMARY KEY,
    cache_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cache_type ON analysis_cache(cache_type);
