from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from pydantic import BaseModel
from typing import Optional, List

app = FastAPI(title="User Management API")

#Database setup (using SQLAlchemy)
engine = create_engine(
    "sqlite:///users.db",
     connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

#Database model
class User(Base):
    __tablename__="users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False, unique=True)
    role = Column(String(100), nullable=False)

#Model need to speak/communicate with the Engine & linking everything together
Base.metadata.create_all(engine)

#Pydantic Models (DataClass)
class UserCreate(BaseModel):
    name:str
    email:str
    role:str

#private model response to protect any private information on an app
class UserResponse(BaseModel):
    id:int
    name:str
    email:str
    role:str

    class Config:
        from_attributes = True


#(Function to)get database running
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

get_db()



@app.get("/")
def root():
    return {"message": "Welcome to the User Management API!"}