from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import Depends, FastAPI, HTTPException, Header, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from passlib.context import CryptContext


DATABASE_URL = os.getenv("EVIDENCE_DB_URL", "sqlite:///./evidence_zbrani.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and not DATABASE_URL.startswith("postgresql+"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
JWT_SECRET = os.getenv("EVIDENCE_JWT_SECRET", "change-me-in-production")
JWT_ALG = "HS256"
ACCESS_TTL_MIN = int(os.getenv("EVIDENCE_ACCESS_TTL_MIN", "120"))
ALLOWED_OWNER_EMAIL = os.getenv("EVIDENCE_ALLOWED_OWNER_EMAIL", "petr.rindos@gmail.com").strip().lower()

ROLE_OWNER = "owner"
ROLE_ADMIN = "admin"
ROLE_EDITOR = "editor"
ROLE_VIEWER = "viewer"
ROLE_ORDER = [ROLE_VIEWER, ROLE_EDITOR, ROLE_ADMIN, ROLE_OWNER]

pwd_ctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    memberships: Mapped[list["Membership"]] = relationship(back_populates="user")


class UserCredential(Base):
    __tablename__ = "user_credentials"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    plain_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    members: Mapped[list["Membership"]] = relationship(back_populates="organization")
    state: Mapped["OrganizationState | None"] = relationship(back_populates="organization", uselist=False)


class Membership(Base):
    __tablename__ = "organization_members"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_org_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    organization: Mapped["Organization"] = relationship(back_populates="members")
    user: Mapped["User"] = relationship(back_populates="memberships")


class OrganizationState(Base):
    __tablename__ = "organization_states"
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    data_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    organization: Mapped["Organization"] = relationship(back_populates="state")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    entity: Mapped[str] = mapped_column(String(80), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    before_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    meta_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)


connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def utc_now() -> datetime:
    return datetime.now(UTC)


def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_ctx.verify(password, password_hash)


def save_user_plain_password(db: Session, *, user_id: int, plain_password: str) -> None:
    rec = db.get(UserCredential, user_id)
    if not rec:
        rec = UserCredential(user_id=user_id, plain_password=plain_password, updated_at=utc_now())
        db.add(rec)
        return
    rec.plain_password = plain_password
    rec.updated_at = utc_now()


def normalize_state(data: dict[str, Any] | None) -> dict[str, Any]:
    d = data if isinstance(data, dict) else {}
    return {
        "holder": d.get("holder", {}) if isinstance(d.get("holder", {}), dict) else {},
        "vyjimky": d.get("vyjimky", []) if isinstance(d.get("vyjimky", []), list) else [],
        "aprobace": d.get("aprobace", []) if isinstance(d.get("aprobace", []), list) else [],
        "registrovaneZbrane": d.get("registrovaneZbrane", []) if isinstance(d.get("registrovaneZbrane", []), list) else [],
        "streleby": d.get("streleby", []) if isinstance(d.get("streleby", []), list) else [],
        "nakupy": d.get("nakupy", []) if isinstance(d.get("nakupy", []), list) else [],
    }


def create_token(*, user_id: int, organization_id: int, role: str) -> str:
    exp = utc_now() + timedelta(minutes=ACCESS_TTL_MIN)
    payload = {"sub": str(user_id), "org": organization_id, "role": role, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


@dataclass
class AuthContext:
    user: User
    organization_id: int
    role: str
    token: str


def parse_bearer_token(auth_header: str | None) -> str:
    if not auth_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chybí Authorization header.")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization musí být Bearer token.")
    return parts[1]


def role_allows(role: str, required: str) -> bool:
    return ROLE_ORDER.index(role) >= ROLE_ORDER.index(required)


def log_audit(
    db: Session,
    *,
    organization_id: int,
    actor_user_id: int | None,
    action: str,
    entity: str,
    entity_id: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    meta: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            entity=entity,
            entity_id=entity_id,
            before_json=before,
            after_json=after,
            meta_json=meta,
        )
    )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_auth_context(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> AuthContext:
    token = parse_bearer_token(authorization)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Neplatný token.") from exc

    user_id_raw = payload.get("sub")
    org_id_raw = payload.get("org")
    role = payload.get("role")
    if not user_id_raw or not org_id_raw or role not in ROLE_ORDER:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token je neplatný nebo nekompletní.")

    user = db.get(User, int(user_id_raw))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Uživatel není dostupný.")

    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id == int(org_id_raw),
        )
    )
    if not membership:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Členství v organizaci nenalezeno.")

    return AuthContext(user=user, organization_id=int(org_id_raw), role=membership.role, token=token)


def require_role(required_role: str):
    def _checker(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if not role_allows(ctx.role, required_role):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Nedostatečná oprávnění.")
        return ctx

    return _checker


class RegisterOwnerIn(BaseModel):
    organization_name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    organization_id: int | None = None


class CreateMemberIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)
    role: str = Field(default=ROLE_VIEWER)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    organization_id: int


class MeOut(BaseModel):
    user_id: int
    email: str
    full_name: str | None
    organization_id: int
    role: str


class MemberOut(BaseModel):
    user_id: int
    email: str
    full_name: str | None
    role: str
    created_at: datetime


class StateOut(BaseModel):
    data: dict[str, Any]
    updated_at: datetime | None = None
    updated_by_user_id: int | None = None


class StateIn(BaseModel):
    data: dict[str, Any]


class AuditOut(BaseModel):
    id: int
    action: str
    entity: str
    entity_id: str | None
    actor_user_id: int | None
    before_json: dict[str, Any] | None
    after_json: dict[str, Any] | None
    meta_json: dict[str, Any] | None
    created_at: datetime


class AdminGenerateIn(BaseModel):
    teams_count: int = Field(default=1, ge=1, le=30)
    users_per_team: int = Field(default=3, ge=1, le=30)


class AdminAddTeamIn(BaseModel):
    organization_name: str = Field(min_length=2, max_length=255)


def ensure_allowed_owner_email(ctx: AuthContext) -> None:
    actor_email = str(ctx.user.email or "").strip().lower()
    if actor_email != ALLOWED_OWNER_EMAIL:
        raise HTTPException(status_code=403, detail="Tato operace je povolena jen pro autorizovaný e-mail.")


app = FastAPI(title="Evidence zbraní API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/register-owner", response_model=TokenOut)
def register_owner(payload: RegisterOwnerIn, db: Session = Depends(get_db)) -> TokenOut:
    requested_email = payload.email.lower().strip()
    if requested_email != ALLOWED_OWNER_EMAIL:
        raise HTTPException(
            status_code=403,
            detail="Registrace týmu je povolená jen pro autorizovaný e-mail.",
        )

    existing = db.scalar(select(User).where(User.email == requested_email))
    if existing:
        raise HTTPException(status_code=409, detail="Uživatel s tímto e-mailem už existuje.")

    org = Organization(name=payload.organization_name.strip())
    db.add(org)
    db.flush()

    user = User(
        email=requested_email,
        password_hash=hash_password(payload.password),
        full_name=(payload.full_name or "").strip() or None,
    )
    db.add(user)
    db.flush()
    save_user_plain_password(db, user_id=user.id, plain_password=payload.password)

    membership = Membership(organization_id=org.id, user_id=user.id, role=ROLE_OWNER)
    db.add(membership)
    db.add(OrganizationState(organization_id=org.id, data_json=normalize_state({}), updated_by_user_id=user.id))
    log_audit(
        db,
        organization_id=org.id,
        actor_user_id=user.id,
        action="organization.create",
        entity="organization",
        entity_id=str(org.id),
        after={"organization_name": org.name, "owner_email": user.email},
    )
    db.commit()

    token = create_token(user_id=user.id, organization_id=org.id, role=ROLE_OWNER)
    return TokenOut(access_token=token, role=ROLE_OWNER, organization_id=org.id)


@app.post("/api/auth/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)) -> TokenOut:
    user = db.scalar(select(User).where(User.email == payload.email.lower().strip()))
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Neplatný e-mail nebo heslo.")
    save_user_plain_password(db, user_id=user.id, plain_password=payload.password)
    db.commit()

    memberships = db.scalars(select(Membership).where(Membership.user_id == user.id)).all()
    if not memberships:
        raise HTTPException(status_code=403, detail="Uživatel není členem žádné organizace.")

    membership = None
    if payload.organization_id is not None:
        for m in memberships:
            if m.organization_id == payload.organization_id:
                membership = m
                break
        if not membership:
            raise HTTPException(status_code=403, detail="Uživatel není členem vybrané organizace.")
    else:
        membership = memberships[0]

    token = create_token(user_id=user.id, organization_id=membership.organization_id, role=membership.role)
    return TokenOut(access_token=token, role=membership.role, organization_id=membership.organization_id)


@app.get("/api/auth/me", response_model=MeOut)
def me(ctx: AuthContext = Depends(require_role(ROLE_VIEWER))) -> MeOut:
    return MeOut(
        user_id=ctx.user.id,
        email=ctx.user.email,
        full_name=ctx.user.full_name,
        organization_id=ctx.organization_id,
        role=ctx.role,
    )


@app.post("/api/admin/teams")
def admin_add_team(
    payload: AdminAddTeamIn,
    ctx: AuthContext = Depends(require_role(ROLE_VIEWER)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_allowed_owner_email(ctx)

    team_name = payload.organization_name.strip()
    if not team_name:
        raise HTTPException(status_code=400, detail="Název týmu je povinný.")

    org = Organization(name=team_name)
    db.add(org)
    db.flush()

    db.add(Membership(organization_id=org.id, user_id=ctx.user.id, role=ROLE_OWNER))
    db.add(
        OrganizationState(
            organization_id=org.id,
            data_json=normalize_state({}),
            updated_by_user_id=ctx.user.id,
            updated_at=utc_now(),
        )
    )
    log_audit(
        db,
        organization_id=org.id,
        actor_user_id=ctx.user.id,
        action="admin.team.create",
        entity="organization",
        entity_id=str(org.id),
        after={"organization_name": org.name, "created_by": ctx.user.email},
    )
    db.commit()
    return {"organization_id": org.id, "organization_name": org.name}


@app.get("/api/org/members", response_model=list[MemberOut])
def list_members(ctx: AuthContext = Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)) -> list[MemberOut]:
    rows = db.scalars(
        select(Membership).where(Membership.organization_id == ctx.organization_id).order_by(Membership.created_at.desc())
    ).all()
    out: list[MemberOut] = []
    for m in rows:
        user = db.get(User, m.user_id)
        if not user:
            continue
        out.append(
            MemberOut(
                user_id=user.id,
                email=user.email,
                full_name=user.full_name,
                role=m.role,
                created_at=m.created_at,
            )
        )
    return out


@app.post("/api/org/members", response_model=MemberOut)
def create_member(
    payload: CreateMemberIn,
    ctx: AuthContext = Depends(require_role(ROLE_ADMIN)),
    db: Session = Depends(get_db),
) -> MemberOut:
    role = payload.role.strip().lower()
    if role not in (ROLE_VIEWER, ROLE_EDITOR, ROLE_ADMIN):
        raise HTTPException(status_code=400, detail="Neplatná role. Použijte viewer/editor/admin.")
    if ctx.role != ROLE_OWNER and role == ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Admin může vytvářet jen viewer/editor.")

    existing_user = db.scalar(select(User).where(User.email == payload.email.lower().strip()))
    if existing_user:
        already = db.scalar(
            select(Membership).where(
                Membership.organization_id == ctx.organization_id,
                Membership.user_id == existing_user.id,
            )
        )
        if already:
            raise HTTPException(status_code=409, detail="Uživatel už je členem organizace.")
        user = existing_user
        user.password_hash = hash_password(payload.password)
        save_user_plain_password(db, user_id=user.id, plain_password=payload.password)
    else:
        user = User(
            email=payload.email.lower().strip(),
            password_hash=hash_password(payload.password),
            full_name=(payload.full_name or "").strip() or None,
        )
        db.add(user)
        db.flush()
        save_user_plain_password(db, user_id=user.id, plain_password=payload.password)

    member = Membership(organization_id=ctx.organization_id, user_id=user.id, role=role)
    db.add(member)
    log_audit(
        db,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user.id,
        action="member.create",
        entity="organization_member",
        entity_id=str(user.id),
        after={"user_id": user.id, "email": user.email, "role": role},
    )
    db.commit()
    return MemberOut(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=role,
        created_at=member.created_at,
    )


@app.get("/api/admin/users-list")
def admin_list_users(
    ctx: AuthContext = Depends(require_role(ROLE_VIEWER)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_allowed_owner_email(ctx)

    orgs = db.scalars(select(Organization).order_by(Organization.name.asc())).all()
    org_map = {o.id: o for o in orgs}
    rows = db.scalars(select(Membership).order_by(Membership.organization_id.asc(), Membership.created_at.asc())).all()

    users: list[dict[str, Any]] = []
    for m in rows:
        user = db.get(User, m.user_id)
        org = org_map.get(m.organization_id)
        if not user or not org:
            continue
        cred = db.get(UserCredential, user.id)
        users.append(
            {
                "membership_id": m.id,
                "user_id": user.id,
                "email": user.email,
                "password": cred.plain_password if cred else None,
                "full_name": user.full_name,
                "team_id": org.id,
                "team_name": org.name,
                "role": m.role,
                "created_at": m.created_at.isoformat() if m.created_at else None,
            }
        )

    teams = [{"team_id": o.id, "team_name": o.name} for o in orgs]
    return {"teams": teams, "users": users}


@app.get("/api/admin/teams-list")
def admin_list_teams(
    ctx: AuthContext = Depends(require_role(ROLE_VIEWER)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_allowed_owner_email(ctx)

    orgs = db.scalars(select(Organization).order_by(Organization.name.asc())).all()
    rows: list[dict[str, Any]] = []
    for org in orgs:
        members_total = db.scalars(select(Membership).where(Membership.organization_id == org.id)).all()
        rows.append(
            {
                "team_id": org.id,
                "team_name": org.name,
                "members_count": len(members_total),
                "created_at": org.created_at.isoformat() if org.created_at else None,
            }
        )
    return {"teams": rows}


@app.delete("/api/admin/teams/{team_id}")
def admin_delete_team(
    team_id: int,
    ctx: AuthContext = Depends(require_role(ROLE_VIEWER)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_allowed_owner_email(ctx)
    if team_id == ctx.organization_id:
        raise HTTPException(status_code=400, detail="Nelze vymazat právě aktivní tým.")

    org = db.get(Organization, team_id)
    if not org:
        raise HTTPException(status_code=404, detail="Tým nebyl nalezen.")

    members = db.scalars(select(Membership).where(Membership.organization_id == team_id)).all()
    member_user_ids = [m.user_id for m in members]
    for m in members:
        db.delete(m)
    state = db.get(OrganizationState, team_id)
    if state:
        db.delete(state)
    logs = db.scalars(select(AuditLog).where(AuditLog.organization_id == team_id)).all()
    for lg in logs:
        db.delete(lg)

    for user_id in member_user_ids:
        has_other = db.scalar(select(Membership).where(Membership.user_id == user_id).limit(1))
        if has_other:
            continue
        cred = db.get(UserCredential, user_id)
        if cred:
            db.delete(cred)
        user = db.get(User, user_id)
        if user:
            db.delete(user)

    removed = {"team_id": org.id, "team_name": org.name}
    db.delete(org)
    db.commit()
    return {"removed": removed}


@app.delete("/api/admin/members/{membership_id}")
def admin_remove_member(
    membership_id: int,
    ctx: AuthContext = Depends(require_role(ROLE_VIEWER)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_allowed_owner_email(ctx)

    membership = db.get(Membership, membership_id)
    if not membership:
        raise HTTPException(status_code=404, detail="Členství nebylo nalezeno.")
    if membership.user_id == ctx.user.id:
        raise HTTPException(status_code=400, detail="Nelze odebrat právě přihlášeného uživatele.")

    user = db.get(User, membership.user_id)
    org = db.get(Organization, membership.organization_id)
    removed = {
        "membership_id": membership.id,
        "user_id": membership.user_id,
        "organization_id": membership.organization_id,
        "email": user.email if user else None,
        "team_name": org.name if org else None,
    }

    db.delete(membership)
    db.flush()

    still_member = db.scalar(
        select(Membership).where(Membership.user_id == removed["user_id"]).limit(1)
    )
    if not still_member and user:
        db.delete(user)

    if org:
        log_audit(
            db,
            organization_id=org.id,
            actor_user_id=ctx.user.id,
            action="admin.member.delete",
            entity="organization_member",
            entity_id=str(removed["membership_id"]),
            before=removed,
            meta={"deleted_by": ctx.user.email},
        )

    db.commit()
    return {"removed": removed}


@app.get("/api/state", response_model=StateOut)
def get_state(ctx: AuthContext = Depends(require_role(ROLE_VIEWER)), db: Session = Depends(get_db)) -> StateOut:
    row = db.get(OrganizationState, ctx.organization_id)
    if not row:
        row = OrganizationState(
            organization_id=ctx.organization_id,
            data_json=normalize_state({}),
            updated_by_user_id=ctx.user.id,
            updated_at=utc_now(),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    return StateOut(data=normalize_state(row.data_json), updated_at=row.updated_at, updated_by_user_id=row.updated_by_user_id)


@app.put("/api/state", response_model=StateOut)
def put_state(
    payload: StateIn,
    ctx: AuthContext = Depends(require_role(ROLE_EDITOR)),
    db: Session = Depends(get_db),
) -> StateOut:
    row = db.get(OrganizationState, ctx.organization_id)
    new_state = normalize_state(payload.data)
    if not row:
        row = OrganizationState(
            organization_id=ctx.organization_id,
            data_json=new_state,
            updated_by_user_id=ctx.user.id,
            updated_at=utc_now(),
        )
        db.add(row)
        before_state = None
    else:
        before_state = normalize_state(row.data_json)
        row.data_json = new_state
        row.updated_by_user_id = ctx.user.id
        row.updated_at = utc_now()

    log_audit(
        db,
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user.id,
        action="state.update",
        entity="organization_state",
        entity_id=str(ctx.organization_id),
        before=before_state,
        after=new_state,
    )
    db.commit()
    db.refresh(row)
    return StateOut(data=normalize_state(row.data_json), updated_at=row.updated_at, updated_by_user_id=row.updated_by_user_id)


@app.get("/api/audit", response_model=list[AuditOut])
def get_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(require_role(ROLE_ADMIN)),
    db: Session = Depends(get_db),
) -> list[AuditOut]:
    rows = db.scalars(
        select(AuditLog)
        .where(AuditLog.organization_id == ctx.organization_id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return [
        AuditOut(
            id=r.id,
            action=r.action,
            entity=r.entity,
            entity_id=r.entity_id,
            actor_user_id=r.actor_user_id,
            before_json=r.before_json,
            after_json=r.after_json,
            meta_json=r.meta_json,
            created_at=r.created_at,
        )
        for r in rows
    ]


@app.post("/api/admin/generate-teams-users")
def admin_generate_teams_users(
    payload: AdminGenerateIn,
    ctx: AuthContext = Depends(require_role(ROLE_VIEWER)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    ensure_allowed_owner_email(ctx)
    actor_email = str(ctx.user.email or "").strip().lower()

    created: list[dict[str, Any]] = []
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M")

    for t_idx in range(1, payload.teams_count + 1):
        org_name = f"Team {stamp}-{t_idx}"
        org = Organization(name=org_name)
        db.add(org)
        db.flush()

        team_users: list[dict[str, Any]] = []
        for u_idx in range(1, payload.users_per_team + 1):
            local = f"team{stamp}{t_idx:02d}u{u_idx:02d}_{secrets.token_hex(2)}"
            email = f"{local}@example.local"
            password = "Pw_" + secrets.token_urlsafe(10)
            role = ROLE_ADMIN if u_idx == 1 else ROLE_EDITOR
            user = User(
                email=email,
                password_hash=hash_password(password),
                full_name=f"User {t_idx}-{u_idx}",
            )
            db.add(user)
            db.flush()
            save_user_plain_password(db, user_id=user.id, plain_password=password)
            db.add(Membership(organization_id=org.id, user_id=user.id, role=role))
            team_users.append({"email": email, "password": password, "role": role})

        db.add(
            OrganizationState(
                organization_id=org.id,
                data_json=normalize_state({}),
                updated_by_user_id=ctx.user.id,
            )
        )
        log_audit(
            db,
            organization_id=org.id,
            actor_user_id=ctx.user.id,
            action="admin.seed.generate",
            entity="organization",
            entity_id=str(org.id),
            after={"organization_name": org_name, "users_count": len(team_users)},
            meta={"generated_by": actor_email},
        )
        created.append({"organization_id": org.id, "organization_name": org_name, "users": team_users})

    db.commit()
    return {
        "created_teams": created,
        "generated_at": datetime.now(UTC).isoformat(),
        "generated_by": actor_email,
    }
