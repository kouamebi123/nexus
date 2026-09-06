import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("SEED_DEMO", "false")
os.environ.setdefault("ENABLE_LIVE_PUBLIC_DATA", "false")

from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


def auth_headers():
    import uuid
    email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    password = "TestPass123!"
    r = client.post("/api/auth/register", json={"email": email, "password": password, "full_name": "Test", "company": "Nexus"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_project_geometry_analysis_flow():
    h = auth_headers()
    p = client.post("/api/projects", headers=h, json={"name": "Site test", "client_name": "Client", "address": "Rennes", "description": "", "status": "analysis"})
    assert p.status_code == 200
    pid = p.json()["id"]
    feature = {"type":"Feature","properties":{},"geometry":{"type":"Polygon","coordinates":[[[-1.678,48.117],[-1.677,48.117],[-1.677,48.118],[-1.678,48.118],[-1.678,48.117]]]}}
    g = client.post(f"/api/projects/{pid}/geometries", headers=h, json={"name":"Toiture","feature":feature,"style":{}})
    assert g.status_code == 200
    payload = {"surface_m2":0,"annual_consumption_kwh":12000,"panel_efficiency":0.22,"installation_cost_per_kwc":1450,"electricity_price":0.25,"resale_price":0.13,"annual_irradiation_kwh_m2":1250,"orientation_deg":180,"slope_deg":30,"installation_mode":"autoconsommation","technology":"monocristallin"}
    a = client.post(f"/api/projects/{pid}/analyze", headers=h, json=payload)
    assert a.status_code == 200, a.text
    data = a.json()
    assert data["power_kwc"] > 0
    assert data["annual_production_kwh"] > 0
    assert data["capex_eur"] > 0
    report = client.get(f"/api/projects/{pid}/report.pdf", headers=h)
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("application/pdf")
    assert report.content[:4] == b"%PDF"


def test_geojson_export():
    h = auth_headers()
    p = client.post("/api/projects", headers=h, json={"name": "Export", "client_name": "", "address": "", "description": "", "status": "draft"}).json()
    r = client.get(f"/api/projects/{p['id']}/export/geojson", headers=h)
    assert r.status_code == 200
    assert r.json()["type"] == "FeatureCollection"
