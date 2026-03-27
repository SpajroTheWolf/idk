from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker, declarative_base

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MODEL
class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True)
    password = Column(String)

Base.metadata.create_all(bind=engine)

# SCHEMA
class LoginData(BaseModel):
    username: str
    password: str

# UTILS
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

# REGISTER
@app.post("/register")
def register(data: LoginData):
    db = SessionLocal()

    user = db.query(User).filter(User.username == data.username).first()
    if user:
        raise HTTPException(status_code=400, detail="User exists")

    hashed = get_password_hash(data.password)
    new_user = User(username=data.username, password=hashed)

    db.add(new_user)
    db.commit()
    db.close()

    return {"msg": "User created"}

# LOGIN
@app.post("/login")
def login(data: LoginData):
    db = SessionLocal()

    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.password):
        db.close()
        raise HTTPException(status_code=401, detail="Bad credentials")

    token = jwt.encode({"sub": user.username}, SECRET_KEY, algorithm=ALGORITHM)

    db.close()
    return {"access_token": token}