from __future__ import annotations

import hashlib
import io
import json
import math
import os
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import jwt
import shapefile
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas
from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'nexus.db'}")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-change-me-" + secrets.token_hex(12))
JWT_ALGORITHM = "HS256"
TOKEN_HOURS = 24
LIVE_PUBLIC_DATA = os.getenv("ENABLE_LIVE_PUBLIC_DATA", "true").lower() in {"1", "true", "yes"}

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine_kwargs = {"future": True, "pool_pre_ping": True, "connect_args": connect_args}
if DATABASE_URL == "sqlite:///:memory:":
    engine_kwargs["poolclass"] = StaticPool
engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(160), default="")
    company: Mapped[str] = mapped_column(String(160), default="")
    role: Mapped[str] = mapped_column(String(40), default="manager")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    client_name: Mapped[str] = mapped_column(String(200), default="")
    address: Mapped[str] = mapped_column(String(300), default="")
    status: Mapped[str] = mapped_column(String(40), default="draft")
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class Geometry(Base):
    __tablename__ = "geometries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160), default="Objet")
    feature: Mapped[dict[str, Any]] = mapped_column(JSON)
    style: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Bookmark(Base):
    __tablename__ = "bookmarks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    lat: Mapped[float] = mapped_column(Float)
    lon: Mapped[float] = mapped_column(Float)
    zoom: Mapped[float] = mapped_column(Float, default=14)


class Feasibility(Base):
    __tablename__ = "feasibility"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), unique=True, index=True)
    surface_m2: Mapped[float] = mapped_column(Float, default=0)
    annual_consumption_kwh: Mapped[float] = mapped_column(Float, default=12000)
    panel_efficiency: Mapped[float] = mapped_column(Float, default=0.22)
    installation_cost_per_kwc: Mapped[float] = mapped_column(Float, default=1450)
    electricity_price: Mapped[float] = mapped_column(Float, default=0.25)
    resale_price: Mapped[float] = mapped_column(Float, default=0.13)
    annual_irradiation_kwh_m2: Mapped[float] = mapped_column(Float, default=1250)
    orientation_deg: Mapped[float] = mapped_column(Float, default=180)
    slope_deg: Mapped[float] = mapped_column(Float, default=30)
    installation_mode: Mapped[str] = mapped_column(String(40), default="autoconsommation")
    technology: Mapped[str] = mapped_column(String(40), default="monocristallin")
    results: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    regulatory: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)

app = FastAPI(title="Nexus API", version="1.0.0", description="Plateforme géospatiale ENR")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
security = HTTPBearer(auto_error=False)


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2_sha256$210000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, rounds, salt_hex, digest_hex = stored.split("$", 3)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return secrets.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def token_for(user: User) -> str:
    payload = {"sub": str(user.id), "email": user.email, "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security), db: Session = Depends(db_session)) -> User:
    if not credentials:
        raise HTTPException(401, "Authentification requise")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = db.get(User, int(payload["sub"]))
    except Exception:
        user = None
    if not user:
        raise HTTPException(401, "Session invalide ou expirée")
    return user


def owned_project(project_id: int, user: User, db: Session) -> Project:
    p = db.scalar(select(Project).where(Project.id == project_id, Project.owner_id == user.id))
    if not p:
        raise HTTPException(404, "Projet introuvable")
    return p


def project_dict(p: Project) -> dict[str, Any]:
    return {"id": p.id, "name": p.name, "client_name": p.client_name, "address": p.address, "status": p.status,
            "description": p.description, "created_at": p.created_at.isoformat(), "updated_at": p.updated_at.isoformat()}


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = ""
    company: str = ""


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ProjectIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    client_name: str = ""
    address: str = ""
    description: str = ""
    status: str = "draft"


class GeometryIn(BaseModel):
    name: str = "Objet"
    feature: dict[str, Any]
    style: dict[str, Any] = Field(default_factory=dict)


class BookmarkIn(BaseModel):
    name: str
    lat: float
    lon: float
    zoom: float = 14


class FeasibilityIn(BaseModel):
    surface_m2: float = 0
    annual_consumption_kwh: float = 12000
    panel_efficiency: float = 0.22
    installation_cost_per_kwc: float = 1450
    electricity_price: float = 0.25
    resale_price: float = 0.13
    annual_irradiation_kwh_m2: float = 1250
    orientation_deg: float = 180
    slope_deg: float = 30
    installation_mode: str = "autoconsommation"
    technology: str = "monocristallin"


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Nexus API", "version": "1.0.0", "database": "sqlite" if DATABASE_URL.startswith("sqlite") else "postgresql"}


@app.post("/api/auth/register")
def register(payload: RegisterIn, db: Session = Depends(db_session)):
    if db.scalar(select(User).where(User.email == payload.email.lower())):
        raise HTTPException(409, "Cette adresse e-mail est déjà utilisée")
    user = User(email=payload.email.lower(), password_hash=hash_password(payload.password), full_name=payload.full_name, company=payload.company)
    db.add(user); db.commit(); db.refresh(user)
    return {"token": token_for(user), "user": {"id": user.id, "email": user.email, "full_name": user.full_name, "company": user.company, "role": user.role}}


@app.post("/api/auth/login")
def login(payload: LoginIn, db: Session = Depends(db_session)):
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "E-mail ou mot de passe incorrect")
    return {"token": token_for(user), "user": {"id": user.id, "email": user.email, "full_name": user.full_name, "company": user.company, "role": user.role}}


@app.get("/api/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "full_name": user.full_name, "company": user.company, "role": user.role}


@app.get("/api/projects")
def list_projects(user: User = Depends(current_user), db: Session = Depends(db_session)):
    return [project_dict(p) for p in db.scalars(select(Project).where(Project.owner_id == user.id).order_by(Project.updated_at.desc())).all()]


@app.post("/api/projects")
def create_project(payload: ProjectIn, user: User = Depends(current_user), db: Session = Depends(db_session)):
    p = Project(owner_id=user.id, **payload.model_dump())
    db.add(p); db.commit(); db.refresh(p)
    return project_dict(p)


@app.get("/api/projects/{project_id}")
def get_project(project_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    return project_dict(owned_project(project_id, user, db))


@app.put("/api/projects/{project_id}")
def update_project(project_id: int, payload: ProjectIn, user: User = Depends(current_user), db: Session = Depends(db_session)):
    p = owned_project(project_id, user, db)
    for k, v in payload.model_dump().items(): setattr(p, k, v)
    p.updated_at = datetime.now(timezone.utc); db.commit(); return project_dict(p)


@app.delete("/api/projects/{project_id}", status_code=204)
def delete_project(project_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    p = owned_project(project_id, user, db)
    for model in (Geometry, Bookmark, Feasibility):
        for row in db.scalars(select(model).where(model.project_id == p.id)).all(): db.delete(row)
    db.delete(p); db.commit(); return Response(status_code=204)


@app.get("/api/projects/{project_id}/geometries")
def list_geometries(project_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    rows = db.scalars(select(Geometry).where(Geometry.project_id == project_id).order_by(Geometry.id)).all()
    return [{"id": g.id, "name": g.name, "feature": g.feature, "style": g.style} for g in rows]


@app.post("/api/projects/{project_id}/geometries")
def add_geometry(project_id: int, payload: GeometryIn, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    g = Geometry(project_id=project_id, **payload.model_dump()); db.add(g); db.commit(); db.refresh(g)
    return {"id": g.id, "name": g.name, "feature": g.feature, "style": g.style}


@app.put("/api/projects/{project_id}/geometries/{geom_id}")
def update_geometry(project_id: int, geom_id: int, payload: GeometryIn, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    g = db.scalar(select(Geometry).where(Geometry.id == geom_id, Geometry.project_id == project_id))
    if not g: raise HTTPException(404, "Géométrie introuvable")
    g.name, g.feature, g.style = payload.name, payload.feature, payload.style; db.commit()
    return {"id": g.id, "name": g.name, "feature": g.feature, "style": g.style}


@app.delete("/api/projects/{project_id}/geometries/{geom_id}", status_code=204)
def remove_geometry(project_id: int, geom_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    g = db.scalar(select(Geometry).where(Geometry.id == geom_id, Geometry.project_id == project_id))
    if not g: raise HTTPException(404, "Géométrie introuvable")
    db.delete(g); db.commit(); return Response(status_code=204)


@app.get("/api/projects/{project_id}/bookmarks")
def list_bookmarks(project_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    return [{"id": b.id, "name": b.name, "lat": b.lat, "lon": b.lon, "zoom": b.zoom} for b in db.scalars(select(Bookmark).where(Bookmark.project_id == project_id)).all()]


@app.post("/api/projects/{project_id}/bookmarks")
def add_bookmark(project_id: int, payload: BookmarkIn, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db); b = Bookmark(project_id=project_id, **payload.model_dump()); db.add(b); db.commit(); db.refresh(b)
    return {"id": b.id, **payload.model_dump()}


@app.delete("/api/projects/{project_id}/bookmarks/{bookmark_id}", status_code=204)
def remove_bookmark(project_id: int, bookmark_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    b = db.scalar(select(Bookmark).where(Bookmark.id == bookmark_id, Bookmark.project_id == project_id))
    if not b: raise HTTPException(404, "Signet introuvable")
    db.delete(b); db.commit(); return Response(status_code=204)


def ring_area_m2(coords: list[list[float]]) -> float:
    if len(coords) < 3: return 0.0
    lat0 = math.radians(sum(p[1] for p in coords) / len(coords))
    xy = [(math.radians(p[0]) * 6371008.8 * math.cos(lat0), math.radians(p[1]) * 6371008.8) for p in coords]
    return abs(sum(xy[i][0] * xy[(i+1)%len(xy)][1] - xy[(i+1)%len(xy)][0] * xy[i][1] for i in range(len(xy))) / 2)


def feature_area(feature: dict[str, Any]) -> float:
    geom = (feature or {}).get("geometry", feature or {})
    t, c = geom.get("type"), geom.get("coordinates", [])
    if t == "Polygon" and c: return max(0.0, ring_area_m2(c[0]) - sum(ring_area_m2(r) for r in c[1:]))
    if t == "MultiPolygon": return sum(max(0.0, ring_area_m2(p[0]) - sum(ring_area_m2(r) for r in p[1:])) for p in c if p)
    return 0.0


def pick_analysis_geometry(project_id: int, db: Session) -> dict[str, Any] | None:
    rows = db.scalars(select(Geometry).where(Geometry.project_id == project_id)).all()
    for g in rows:
        geom = g.feature.get("geometry", g.feature)
        if geom.get("type") in {"Polygon", "MultiPolygon", "Point"}: return geom
    return None


@app.get("/api/projects/{project_id}/feasibility")
def get_feasibility(project_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    f = db.scalar(select(Feasibility).where(Feasibility.project_id == project_id))
    if not f: return FeasibilityIn().model_dump() | {"results": {}, "regulatory": {}}
    return {k: getattr(f, k) for k in FeasibilityIn.model_fields} | {"results": f.results or {}, "regulatory": f.regulatory or {}}


@app.post("/api/projects/{project_id}/feasibility")
def save_feasibility(project_id: int, payload: FeasibilityIn, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    f = db.scalar(select(Feasibility).where(Feasibility.project_id == project_id)) or Feasibility(project_id=project_id)
    for k, v in payload.model_dump().items(): setattr(f, k, v)
    if f.id is None: db.add(f)
    db.commit(); return {"saved": True}


@app.post("/api/projects/{project_id}/analyze")
def analyze(project_id: int, payload: FeasibilityIn, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    geoms = db.scalars(select(Geometry).where(Geometry.project_id == project_id)).all()
    measured = sum(feature_area(g.feature) for g in geoms)
    surface = payload.surface_m2 or measured or 100
    usable = surface * 0.78
    panel_area = 2.0 if payload.technology != "bifacial" else 2.1
    panel_power_kw = 0.45 if payload.technology != "polycristallin" else 0.40
    panels = max(1, math.floor(usable / panel_area))
    kwc = panels * panel_power_kw
    orientation_factor = max(0.65, 1 - min(abs(payload.orientation_deg - 180), 180) / 900)
    slope_factor = max(0.82, 1 - abs(payload.slope_deg - 30) / 220)
    yield_kwh = kwc * payload.annual_irradiation_kwh_m2 * 0.82 * orientation_factor * slope_factor
    self_use = min(yield_kwh, payload.annual_consumption_kwh) if payload.installation_mode != "revente" else 0
    sold = max(0, yield_kwh - self_use) if payload.installation_mode != "autoconsommation" else max(0, yield_kwh - self_use) * 0.6
    annual_savings = self_use * payload.electricity_price + sold * payload.resale_price
    capex = kwc * payload.installation_cost_per_kwc
    simple_payback = capex / annual_savings if annual_savings > 0 else None
    roi_25 = ((annual_savings * 25 - capex) / capex * 100) if capex else 0
    avoided_co2_t = yield_kwh * 0.055 / 1000
    results = {
        "surface_measured_m2": round(measured, 1), "surface_used_m2": round(surface, 1), "surface_exploitable_m2": round(usable, 1),
        "panels": panels, "power_kwc": round(kwc, 2), "annual_production_kwh": round(yield_kwh),
        "orientation_optimal_deg": 180, "slope_optimal_deg": 30, "orientation_factor": round(orientation_factor, 3), "slope_factor": round(slope_factor, 3),
        "capex_eur": round(capex, 2), "annual_savings_eur": round(annual_savings, 2), "simple_payback_years": round(simple_payback, 1) if simple_payback else None,
        "roi_25y_percent": round(roi_25, 1), "avoided_co2_t_per_year": round(avoided_co2_t, 3),
        "recommendation": "Autoconsommation avec vente du surplus" if payload.installation_mode == "autoconsommation" else payload.installation_mode.capitalize(),
        "confidence": "pré-dimensionnement"
    }
    f = db.scalar(select(Feasibility).where(Feasibility.project_id == project_id)) or Feasibility(project_id=project_id)
    for k, v in payload.model_dump().items(): setattr(f, k, v)
    f.surface_m2 = surface; f.results = results
    if f.id is None: db.add(f)
    db.commit()
    return results


async def api_carto(path: str, geom: dict[str, Any]) -> dict[str, Any]:
    if not LIVE_PUBLIC_DATA: return {"type": "FeatureCollection", "features": [], "disabled": True}
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(f"https://apicarto.ign.fr/api/{path}", params={"geom": json.dumps(geom, separators=(",", ":")), "_limit": 50})
            r.raise_for_status(); return r.json()
    except Exception as exc:
        return {"type": "FeatureCollection", "features": [], "error": str(exc)}


@app.post("/api/projects/{project_id}/regulatory")
async def regulatory(project_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    geom = pick_analysis_geometry(project_id, db)
    if not geom: raise HTTPException(400, "Dessinez au moins une zone ou un point sur la carte")
    layers = {
        "urban_zones": await api_carto("gpu/zone-urba", geom),
        "urban_prescriptions": await api_carto("gpu/prescription-surf", geom),
        "natura_habitat": await api_carto("nature/natura-habitat", geom),
        "natura_birds": await api_carto("nature/natura-oiseaux", geom),
        "znieff1": await api_carto("nature/znieff1", geom),
        "znieff2": await api_carto("nature/znieff2", geom),
        "cadastre": await api_carto("cadastre/parcelle", geom),
    }
    summary = {k: len((v or {}).get("features", [])) for k, v in layers.items()}
    result = {"summary": summary, "layers": layers, "checked_at": datetime.now(timezone.utc).isoformat(), "source": "IGN API Carto"}
    f = db.scalar(select(Feasibility).where(Feasibility.project_id == project_id)) or Feasibility(project_id=project_id)
    f.regulatory = result
    if f.id is None: db.add(f)
    db.commit()
    return result


@app.get("/api/geocode")
async def geocode(q: str, user: User = Depends(current_user)):
    if len(q.strip()) < 3: return []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get("https://data.geopf.fr/geocodage/search", params={"q": q, "limit": 6, "index": "address"})
            r.raise_for_status(); data = r.json()
        out = []
        for ft in data.get("features", []):
            props, coords = ft.get("properties", {}), ft.get("geometry", {}).get("coordinates", [0, 0])
            out.append({"label": props.get("label") or props.get("name") or q, "lon": coords[0], "lat": coords[1], "raw": props})
        return out
    except Exception as exc:
        raise HTTPException(502, f"Service de géocodage indisponible: {exc}")


@app.post("/api/projects/{project_id}/import/geojson")
async def import_geojson(project_id: int, file: UploadFile = File(...), user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    try: data = json.loads((await file.read()).decode("utf-8"))
    except Exception: raise HTTPException(400, "Fichier GeoJSON invalide")
    feats = data.get("features", []) if data.get("type") == "FeatureCollection" else [data]
    created = 0
    for i, ft in enumerate(feats):
        if ft.get("geometry"):
            db.add(Geometry(project_id=project_id, name=(ft.get("properties") or {}).get("name", f"Import {i+1}"), feature=ft, style={})); created += 1
    db.commit(); return {"created": created}


@app.post("/api/projects/{project_id}/import/shapefile")
async def import_shapefile(project_id: int, file: UploadFile = File(...), user: User = Depends(current_user), db: Session = Depends(db_session)):
    owned_project(project_id, user, db)
    raw = await file.read()
    tmp = ROOT / ".tmp_shape"; tmp.mkdir(exist_ok=True)
    for old in tmp.glob("*"): old.unlink()
    try:
        if file.filename and file.filename.lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw)) as z: z.extractall(tmp)
            shp = next(tmp.glob("*.shp"))
        else:
            shp = tmp / "upload.shp"; shp.write_bytes(raw)
        reader = shapefile.Reader(str(shp))
        fields = [f[0] for f in reader.fields[1:]]
        created = 0
        for i, sr in enumerate(reader.iterShapeRecords()):
            props = dict(zip(fields, sr.record))
            ft = {"type": "Feature", "properties": props, "geometry": sr.shape.__geo_interface__}
            db.add(Geometry(project_id=project_id, name=str(props.get("name") or props.get("nom") or f"Shapefile {i+1}"), feature=ft, style={})); created += 1
        db.commit(); return {"created": created}
    except Exception as exc:
        raise HTTPException(400, f"Shapefile invalide. Pour un Shapefile complet, importez un ZIP contenant .shp/.shx/.dbf : {exc}")


@app.get("/api/projects/{project_id}/export/geojson")
def export_geojson(project_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    p = owned_project(project_id, user, db)
    feats = [g.feature for g in db.scalars(select(Geometry).where(Geometry.project_id == project_id)).all()]
    return JSONResponse({"type": "FeatureCollection", "name": p.name, "features": feats}, headers={"Content-Disposition": f'attachment; filename="nexus-project-{project_id}.geojson"'})


@app.get("/api/projects/{project_id}/export/shapefile")
def export_shapefile(project_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    p = owned_project(project_id, user, db)
    rows = db.scalars(select(Geometry).where(Geometry.project_id == project_id)).all()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        groups = {"point": [], "line": [], "polygon": []}
        for g in rows:
            geom = g.feature.get("geometry", {}); t = geom.get("type", "")
            key = "point" if "Point" in t else "line" if "LineString" in t else "polygon" if "Polygon" in t else None
            if key: groups[key].append(g)
        for key, items in groups.items():
            if not items: continue
            base = ROOT / f".tmp_{project_id}_{key}"
            shape_type = {"point": shapefile.POINT, "line": shapefile.POLYLINE, "polygon": shapefile.POLYGON}[key]
            w = shapefile.Writer(str(base), shapeType=shape_type); w.field("name", "C", size=120)
            for g in items:
                geom = g.feature.get("geometry", {}); c = geom.get("coordinates", []); t = geom.get("type")
                try:
                    if t == "Point": w.point(*c[:2])
                    elif t == "MultiPoint": w.multipoint(c)
                    elif t == "LineString": w.line([c])
                    elif t == "MultiLineString": w.line(c)
                    elif t == "Polygon": w.poly(c)
                    elif t == "MultiPolygon":
                        parts = []
                        for poly in c: parts.extend(poly)
                        w.poly(parts)
                    else: continue
                    w.record(g.name[:120])
                except Exception: continue
            w.close()
            for ext in ("shp", "shx", "dbf"):
                fp = Path(str(base) + f".{ext}")
                if fp.exists(): z.write(fp, f"{key}s.{ext}"); fp.unlink()
            z.writestr(f"{key}s.prj", 'GEOGCS["WGS 84",DATUM["WGS_1984",SPHEROID["WGS 84",6378137,298.257223563]],PRIMEM["Greenwich",0],UNIT["degree",0.0174532925199433]]')
    return Response(out.getvalue(), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{p.name.replace(" ", "-")}-shapefile.zip"'})


def all_coords(geom: dict[str, Any]):
    c = geom.get("coordinates", [])
    def walk(v):
        if isinstance(v, list) and len(v) >= 2 and all(isinstance(x, (int, float)) for x in v[:2]): yield v[0], v[1]
        elif isinstance(v, list):
            for x in v: yield from walk(x)
    yield from walk(c)


@app.get("/api/projects/{project_id}/report.pdf")
def report_pdf(project_id: int, user: User = Depends(current_user), db: Session = Depends(db_session)):
    p = owned_project(project_id, user, db)
    f = db.scalar(select(Feasibility).where(Feasibility.project_id == project_id))
    geoms = db.scalars(select(Geometry).where(Geometry.project_id == project_id)).all()
    buf = io.BytesIO(); c = canvas.Canvas(buf, pagesize=A4); W, H = A4
    c.setTitle(f"Nexus - {p.name}")
    c.setFont("Helvetica-Bold", 22); c.drawString(2*cm, H-2*cm, "Nexus — Étude préalable ENR")
    c.setFont("Helvetica", 11); c.drawString(2*cm, H-2.7*cm, f"Projet : {p.name}"); c.drawString(2*cm, H-3.2*cm, f"Client : {p.client_name or '—'}")
    c.drawString(2*cm, H-3.7*cm, f"Adresse : {p.address or '—'}"); c.drawString(2*cm, H-4.2*cm, f"Généré le {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    y = H-5.2*cm
    c.setFont("Helvetica-Bold", 14); c.drawString(2*cm, y, "Synthèse de faisabilité"); y -= .6*cm
    results = (f.results if f else {}) or {}
    lines = [
        ("Surface étudiée", f"{results.get('surface_used_m2', 0)} m²"), ("Puissance installable", f"{results.get('power_kwc', 0)} kWc"),
        ("Production annuelle estimée", f"{results.get('annual_production_kwh', 0):,.0f} kWh"), ("Investissement estimé", f"{results.get('capex_eur', 0):,.0f} €"),
        ("Économies / revenus annuels", f"{results.get('annual_savings_eur', 0):,.0f} €"), ("Temps de retour simple", f"{results.get('simple_payback_years', '—')} ans"),
        ("CO₂ évité", f"{results.get('avoided_co2_t_per_year', 0)} t/an"),
    ]
    c.setFont("Helvetica", 10)
    for label, value in lines:
        c.drawString(2.2*cm, y, label); c.drawRightString(W-2*cm, y, value); y -= .45*cm
    y -= .3*cm; c.setFont("Helvetica-Bold", 14); c.drawString(2*cm, y, "Carte schématique"); y -= .4*cm
    box_x, box_y, box_w, box_h = 2*cm, y-6.5*cm, W-4*cm, 6.2*cm
    c.rect(box_x, box_y, box_w, box_h)
    coords = [pt for g in geoms for pt in all_coords(g.feature.get("geometry", {}))]
    if coords:
        xs, ys = [p[0] for p in coords], [p[1] for p in coords]; minx,maxx,miny,maxy=min(xs),max(xs),min(ys),max(ys)
        dx,dy=max(maxx-minx,1e-6),max(maxy-miny,1e-6)
        def tx(pt): return box_x+10+(pt[0]-minx)/dx*(box_w-20), box_y+10+(pt[1]-miny)/dy*(box_h-20)
        c.setLineWidth(1.2)
        for g in geoms:
            pts=list(all_coords(g.feature.get("geometry", {})))
            if len(pts)>1:
                path=c.beginPath(); x0,y0=tx(pts[0]); path.moveTo(x0,y0)
                for pt in pts[1:]: x,y2=tx(pt); path.lineTo(x,y2)
                c.drawPath(path)
            elif pts:
                x,y2=tx(pts[0]); c.circle(x,y2,3,fill=1)
    else:
        c.setFont("Helvetica", 10); c.drawCentredString(W/2, box_y+box_h/2, "Aucune géométrie enregistrée")
    y = box_y-0.7*cm; c.setFont("Helvetica-Bold", 12); c.drawString(2*cm, y, "Analyse réglementaire")
    y -= .45*cm; c.setFont("Helvetica", 9)
    reg = (f.regulatory if f else {}) or {}; summary = reg.get("summary", {})
    labels = {"urban_zones":"Zonages PLU", "urban_prescriptions":"Prescriptions", "natura_habitat":"Natura 2000 habitat", "natura_birds":"Natura 2000 oiseaux", "znieff1":"ZNIEFF 1", "znieff2":"ZNIEFF 2", "cadastre":"Parcelles cadastrales"}
    for k, label in labels.items():
        c.drawString(2.2*cm, y, f"{label}: {summary.get(k, 'non vérifié')}"); y -= .34*cm
    c.setFont("Helvetica-Oblique", 7.5); c.drawString(2*cm, 1.2*cm, "Pré-étude indicative : les données publiques et calculs doivent être confirmés par un professionnel avant engagement ou dépôt réglementaire.")
    c.save(); return Response(buf.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="nexus-{project_id}-rapport.pdf"'})


# Seed a demo account only when explicitly enabled (default true in local dev).
def seed_demo():
    if os.getenv("SEED_DEMO", "true").lower() not in {"1","true","yes"}: return
    with SessionLocal() as db:
        if not db.scalar(select(User).where(User.email == "demo@nexus-enr.fr")):
            db.add(User(email="demo@nexus-enr.fr", password_hash=hash_password("Demo123!"), full_name="Compte Démo", company="Nexus Demo")); db.commit()
seed_demo()

app.mount("/assets", StaticFiles(directory=FRONTEND), name="assets")

@app.get("/{path:path}")
def spa(path: str):
    candidate = FRONTEND / path
    if path and candidate.exists() and candidate.is_file(): return FileResponse(candidate)
    return FileResponse(FRONTEND / "index.html")
