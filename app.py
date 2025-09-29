# step045_products_with_auth/app.py
from fastapi import FastAPI, HTTPException, Depends, status, Header
from pydantic import BaseModel
from typing import List, Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, String, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, sessionmaker
import uuid, time

# ======== Config (dev values) ========
JWT_SECRET = "fe466eef482c7def2809f1e80026aa72bcbfcbecd47edada521737ce4a8759d8"
ALG = "HS256"
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ======== DB (SQLite for products) ========
engine = create_engine("sqlite:///./shop.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase): pass

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

# ======== Auth (in-memory users for learning) ========
USERS: dict[str, dict] = {}  # email -> {id, email, pw_hash, role}

class RegisterIn(BaseModel):
    email: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

def make_access_token(sub: str, role: str, ttl=3600):
    now = int(time.time())
    return jwt.encode({"sub": sub, "role": role, "iat": now, "exp": now+ttl}, JWT_SECRET, algorithm=ALG)

def get_current_user(authorization: Optional[str] = Header(default=None, alias="Authorization")):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALG])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    uid = payload.get("sub")
    for u in USERS.values():
        if u["id"] == uid:
            return u
    raise HTTPException(401, "User not found")

# ======== Schemas for products ========
class ProductIn(BaseModel):
    name: str
    price_cents: int

class ProductOut(ProductIn):
    id: str
    class Config: from_attributes = True

# ======== App & routes ========
app = FastAPI(title="Products + Auth (Step 4.5)")

@app.get("/")
def root():
    return {"ok": True, "docs": "/docs"}

# --- Auth routes (in-memory) ---
@app.post("/auth/register")
def register(body: RegisterIn):
    if body.email in USERS:
        raise HTTPException(400, "Email exists")
    USERS[body.email] = {
        "id": str(uuid.uuid4()),
        "email": body.email,
        "pw_hash": pwd.hash(body.password),
        "role": "user"
    }
    return {"ok": True}

@app.post("/auth/login", response_model=TokenOut)
def login(body: RegisterIn):
    u = USERS.get(body.email)
    if not u or not pwd.verify(body.password, u["pw_hash"]):
        raise HTTPException(400, "Invalid credentials")
    return TokenOut(access_token=make_access_token(u["id"], u["role"]))

@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"id": user["id"], "email": user["email"], "role": user["role"]}

# --- Product routes ---
# Public browse
@app.get("/products", response_model=List[ProductOut])
def list_products(db: Session = Depends(get_db)):
    return db.query(Product).all()

# Protected write
@app.post("/products", response_model=ProductOut)
def create_product(body: ProductIn, user=Depends(get_current_user), db: Session = Depends(get_db)):
    p = Product(name=body.name, price_cents=body.price_cents)
    db.add(p); db.commit(); db.refresh(p)
    return p

@app.get("/products/{pid}", response_model=ProductOut)
def get_product(pid: str, db: Session = Depends(get_db)):
    p = db.get(Product, pid)
    if not p: raise HTTPException(404, "Not found")
    return p

@app.delete("/products/{pid}")
def delete_product(pid: str, user=Depends(get_current_user), db: Session = Depends(get_db)):
    p = db.get(Product, pid)
    if not p: raise HTTPException(404, "Not found")
    db.delete(p); db.commit()
    return {"ok": True}
