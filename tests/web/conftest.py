"""Test setup for vai.web: offline, mock backends, temporary results folder."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ["VAI_NO_AUTOAPP"] = "1"      # do not build the module-level app during import
os.environ["VAI_STEP_DELAY"] = "0"      # no pauses in tests
os.environ["VAI_FORCE_MOCK"] = "1"      # tests use mocks even if real packages exist

import pytest
from fastapi.testclient import TestClient

from vai.web.app import create_app
from vai.web.service import Settings

CID = "FIR-1427-2027"


@pytest.fixture()
def client(tmp_path):
    app = create_app(Settings(results_dir=tmp_path / "res", demo_password=""))
    return TestClient(app)


@pytest.fixture()
def done(client):
    r = client.post(f"/api/cases/{CID}/run?wait=true")
    assert r.status_code == 200, r.text
    return client
