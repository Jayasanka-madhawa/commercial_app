# step03_sqlite/app.py
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List
from sqlalchemy import create_engine, String, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, sessionmaker
import uuid

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

class ProductIn(BaseModel):
    name: str
    price_cents: int

class ProductOut(ProductIn):
    id: str
    class Config: from_attributes = True

app = FastAPI(title="Products – SQLite")

@app.get("/products", response_model=List[ProductOut])
def list_products(db: Session = Depends(get_db)):
    return db.query(Product).all()

@app.post("/products", response_model=ProductOut)
def create_product(body: ProductIn, db: Session = Depends(get_db)):
    p = Product(name=body.name, price_cents=body.price_cents)
    db.add(p); db.commit(); db.refresh(p)
    return p

@app.get("/products/{pid}", response_model=ProductOut)
def get_product(pid: str, db: Session = Depends(get_db)):
    p = db.get(Product, pid)
    if not p: raise HTTPException(404, "Not found")
    return p

@app.delete("/products/{pid}")
def delete_product(pid: str, db: Session = Depends(get_db)):
    p = db.get(Product, pid)
    if not p: raise HTTPException(404, "Not found")
    db.delete(p); db.commit()
    return {"ok": True}
