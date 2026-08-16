"""
Shared test fixtures.

Test runs must not contaminate the research corpus. `data/logs/` is the
project's actual data, so the log directory is redirected before any
application module is imported -- application modules open their log store at
import time, so this has to happen first.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_LOG_DIR = REPO_ROOT / "data" / "logs" / "_test"

# Must precede `import target_app.main` anywhere in the suite.
os.environ.setdefault("ADF_LOGGING__LOG_DIR", "data/logs/_test")


@pytest.fixture(scope="session", autouse=True)
def _isolate_test_logs():
    TEST_LOG_DIR.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(TEST_LOG_DIR, ignore_errors=True)


@pytest.fixture(scope="session")
def seeded_db():
    """A freshly seeded target database, isolated from the corpus database."""
    from target_app.db import Database
    from target_app.seed import seed

    path = REPO_ROOT / "data" / "test_target.sqlite3"
    db = Database("sqlite:///data/test_target.sqlite3")
    seed(db, seed_value=20260813)
    yield db
    # Best-effort cleanup: the file is disposable and gitignored, so a
    # lingering OS lock (Windows) must not fail the whole suite.
    try:
        path.unlink(missing_ok=True)
    except PermissionError:
        pass


@pytest.fixture(scope="session")
def client(seeded_db):
    """TestClient bound to the target app, pointed at the test database."""
    os.environ["ADF_DATABASES__TARGET_DSN"] = "sqlite:///data/test_target.sqlite3"

    from fastapi.testclient import TestClient
    import target_app.main as main

    main.db = seeded_db  # the module read the DSN at import; redirect it here
    with TestClient(main.app) as tc:
        yield tc
