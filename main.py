from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker, declarative_base
import secrets

# ---------------- CONFIG ----------------
DATABASE_URL = "sqlite:///./users.db"
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------- MODEL ----------------
class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True)
    password = Column(String)
    api_key = Column(String, unique=True, index=True)

Base.metadata.create_all(bind=engine)

# ---------------- SCHEMAS ----------------
class AuthData(BaseModel):
    username: str
    password: str

# ---------------- UTILS ----------------
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def generate_api_key():
    return secrets.token_hex(32)

# ---------------- REGISTER ----------------
@app.post("/register")
def register(data: AuthData):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == data.username).first()
        if user:
            raise HTTPException(status_code=400, detail="User already exists")

        api_key = generate_api_key()

        new_user = User(
            username=data.username,
            password=hash_password(data.password),
            api_key=api_key
        )

        db.add(new_user)
        db.commit()

        return {
            "message": "User created",
            "api_key": api_key
        }

    finally:
        db.close()

# ---------------- LOGIN (API KEY) ----------------
def get_user_from_key(x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.api_key == x_api_key).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return user
    finally:
        db.close()

# ---------------- PROTECTED ROUTE ----------------
@app.get("/me")
def me(user=Depends(get_user_from_key)):
    return {
        "username": user.username,
        "message": "You are authenticated"
    }
