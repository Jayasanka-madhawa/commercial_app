# step05_db_users/app.py
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import List, Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, String, Integer, UniqueConstraint, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, sessionmaker
import uuid, time, os

# ======== Config ========
JWT_SECRET = os.getenv("JWT_SECRET", "fe466eef482c7def2809f1e80026aa72bcbfcbecd47edada521737ce4a8759d8")  # set a strong secret in env for real use
ALG = "HS256"
ACCESS_TTL = 3600  # 1 hour
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ======== DB (SQLite) ========
engine = create_engine("sqlite:///./shop.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="user")  # user/admin
    __table_args__ = (UniqueConstraint("email", name="uq_user_email"),)

class Product(Base):
    __tablename__ = "products"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String)
    price_cents: Mapped[int] = mapped_column(Integer)

Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# ======== Schemas ========
class RegisterIn(BaseModel):
    email: str
    password: str
    # (keep it simple; we’ll add name/phone later)

class LoginIn(BaseModel):
    email: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ProductIn(BaseModel):
    name: str
    price_cents: int

class ProductOut(ProductIn):
    id: str
    class Config: from_attributes = True

# ======== Auth helpers ========
def make_access_token(sub: str, role: str, ttl=ACCESS_TTL):
    now = int(time.time())
    return jwt.encode({"sub": sub, "role": role, "iat": now, "exp": now + ttl}, JWT_SECRET, algorithm=ALG)

def get_current_user(authorization: Optional[str] = Header(default=None, alias="Authorization"),
                     db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALG])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    uid = payload.get("sub")
    user = db.get(User, uid)
    if not user:
        raise HTTPException(401, "User not found")
    return user

def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user

# ======== App ========
app = FastAPI(title="Step 5 — DB Users + JWT + Products")

@app.get("/")
def root():
    return {"ok": True, "docs": "/docs"}

# --- Auth (persistent users) ---
@app.post("/auth/register")
def register(body: RegisterIn, db: Session = Depends(get_db)):
    exists = db.scalar(select(User).where(User.email == body.email))
    if exists:
        raise HTTPException(400, "Email already registered")
    # first user can be admin if ADMIN_EMAIL matches (optional)
    role = "admin" if os.getenv("ADMIN_EMAIL", "").lower() == body.email.lower() else "user"
    u = User(email=body.email, password_hash=pwd.hash(body.password), role=role)
    db.add(u); db.commit()
    return {"ok": True, "role": role}

@app.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(User.email == body.email))
    if not u or not pwd.verify(body.password, u.password_hash):
        raise HTTPException(400, "Invalid credentials")
    return TokenOut(access_token=make_access_token(u.id, u.role))

@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "role": user.role}

# --- Products ---
@app.get("/products", response_model=List[ProductOut])
def list_products(db: Session = Depends(get_db)):
    return db.query(Product).all()

@app.get("/products/{pid}", response_model=ProductOut)
def get_product(pid: str, db: Session = Depends(get_db)):
    p = db.get(Product, pid)
    if not p: raise HTTPException(404, "Not found")
    return p

# Protected writes (make delete admin-only to demo roles)
@app.post("/products", response_model=ProductOut)
def create_product(body: ProductIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    p = Product(name=body.name, price_cents=body.price_cents)
    db.add(p); db.commit(); db.refresh(p)
    return p

@app.delete("/products/{pid}")
def delete_product(pid: str, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    p = db.get(Product, pid)
    if not p: raise HTTPException(404, "Not found")
    db.delete(p); db.commit()
    return {"ok": True}
