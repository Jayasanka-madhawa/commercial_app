# step05_db_users/app.py
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import List, Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, String, Integer, UniqueConstraint, select ,DateTime, Text ,ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, sessionmaker
import uuid, time, os
import json, datetime as dt


# ======== Config ========
JWT_SECRET = os.getenv("JWT_SECRET", "fe466eef482c7def2809f1e80026aa72bcbfcbecd47edada521737ce4a8759d8")  # set a strong secret in env for real use
ALG = "HS256"
ACCESS_TTL = 3600  # 1 hour
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ======== DB (SQLite) ========
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./shop.db")  # fallback for local
if DB_URL.startswith("postgres://"):
    # Render/Heroku style → SQLAlchemy expects postgresql://
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="user")  # user/admin
    __table_args__ = (UniqueConstraint("email", name="uq_user_email"),)

class Category(Base):
    __tablename__ = "categories"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, index=True)
    slug: Mapped[str] = mapped_column(String, unique=True, index=True)

class Product(Base):
    __tablename__ = "products"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String)
    price_cents: Mapped[int] = mapped_column(Integer)
    category_id: Mapped[str | None] = mapped_column(String, ForeignKey("categories.id"), nullable=True)
    inventory: Mapped[int] = mapped_column(Integer, default=0)  # NEW

class Order(Base):
    __tablename__ = "orders"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String, index=True)
    items_json: Mapped[str] = mapped_column(Text)  # JSON array of items
    total_cents: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, paid, shipped, cancelled
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=lambda: dt.datetime.utcnow())


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

class CategoryIn(BaseModel):
    name: str
    slug: str

class CategoryOut(BaseModel):
    id: str
    name: str
    slug: str
    class Config: from_attributes = True

class ProductIn(BaseModel):
    name: str
    price_cents: int
    category_id: str | None = None
    inventory: int = 0                         # NEW

class ProductOut(ProductIn):
    id: str
    class Config: from_attributes = True

class OrderItem(BaseModel):
    product_id: str
    qty: int

class OrderIn(BaseModel):
    items: List[OrderItem]

class OrderOut(BaseModel):
    id: str
    total_cents: int
    status: str
    created_at: dt.datetime
    items: List[dict]  # [{product_id, name, price_cents, qty}]

class InventoryPatch(BaseModel):
    delta: int  # e.g., +10 to add stock, -2 to remove



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
def list_products(
    q: str | None = None,
    category_id: str | None = None,
    db: Session = Depends(get_db)
):
    stmt = select(Product)
    if q:
        stmt = stmt.where(Product.name.ilike(f"%{q}%"))
    if category_id:
        stmt = stmt.where(Product.category_id == category_id)
    return db.scalars(stmt).all()


@app.get("/products/{pid}", response_model=ProductOut)
def get_product(pid: str, db: Session = Depends(get_db)):
    p = db.get(Product, pid)
    if not p: raise HTTPException(404, "Not found")
    return p

# Protected writes (make delete admin-only to demo roles)
@app.post("/products", response_model=ProductOut)
def create_product(body: ProductIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    p = Product(
        name=body.name,
        price_cents=body.price_cents,
        category_id=body.category_id,
        inventory=body.inventory,
    )
    db.add(p); db.commit(); db.refresh(p)
    return p

@app.delete("/products/{pid}")
def delete_product(pid: str, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    p = db.get(Product, pid)
    if not p: raise HTTPException(404, "Not found")
    db.delete(p); db.commit()
    return {"ok": True}

@app.post("/orders", response_model=OrderOut)
def create_order(body: OrderIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not body.items:
        raise HTTPException(400, "Cart is empty")

    normalized = []
    total = 0

    # 1) validate availability
    prods = {}
    for it in body.items:
        p = db.get(Product, it.product_id)
        if not p:
            raise HTTPException(400, f"Invalid product: {it.product_id}")
        if it.qty <= 0:
            raise HTTPException(400, "Quantity must be >= 1")
        if p.inventory < it.qty:
            raise HTTPException(400, f"Insufficient stock for {p.name} (have {p.inventory}, need {it.qty})")
        prods[it.product_id] = p

    # 2) build normalized items & compute total
    for it in body.items:
        p = prods[it.product_id]
        normalized.append({
            "product_id": p.id,
            "name": p.name,
            "price_cents": p.price_cents,
            "qty": it.qty,
        })
        total += p.price_cents * it.qty

    # 3) decrement stock
    for it in body.items:
        p = prods[it.product_id]
        p.inventory -= it.qty

    order = Order(
        user_id=user.id,
        items_json=json.dumps(normalized),
        total_cents=total,
        status="pending",
    )
    db.add(order)
    db.commit()
    db.refresh(order)

    return OrderOut(
        id=order.id,
        total_cents=order.total_cents,
        status=order.status,
        created_at=order.created_at,
        items=normalized
    )


@app.get("/orders", response_model=List[OrderOut])
def list_orders(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.execute(
        select(Order).where(Order.user_id == user.id).order_by(Order.created_at.desc())
    ).scalars().all()
    out = []
    for o in rows:
        out.append(OrderOut(
            id=o.id,
            total_cents=o.total_cents,
            status=o.status,
            created_at=o.created_at,
            items=json.loads(o.items_json)
        ))
    return out

@app.get("/categories", response_model=List[CategoryOut])
def list_categories(db: Session = Depends(get_db)):
    return db.scalars(select(Category).order_by(Category.name)).all()

@app.post("/categories", response_model=CategoryOut)
def create_category(body: CategoryIn, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.scalar(select(Category).where(Category.slug == body.slug)):
        raise HTTPException(400, "Slug already exists")
    c = Category(name=body.name, slug=body.slug)
    db.add(c); db.commit(); db.refresh(c)
    return c

@app.patch("/products/{pid}/inventory")
def patch_inventory(
    pid: str,
    body: InventoryPatch,
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    p = db.get(Product, pid)
    if not p:
        raise HTTPException(404, "Not found")
    new_qty = p.inventory + body.delta
    if new_qty < 0:
        raise HTTPException(400, f"Inventory cannot be negative (current {p.inventory}, delta {body.delta})")
    p.inventory = new_qty
    db.commit()
    return {"ok": True, "inventory": p.inventory}

@app.get("/healthz")
def health():
    return {"status": "ok"}

