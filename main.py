from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import Optional, List
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta


#Security configurations
SECRET_KEY = "Dev_with_Dam"
ALGORITHM = "HS256"
TOKEN_EXPIRES = 30

pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="User Management API")

#Database setup (using SQLAlchemy)
engine = create_engine(
    "sqlite:///users.db",
     connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

#SQLalchemy Database model
class User(Base):
    __tablename__="users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False, unique=True)
    role = Column(String(100), nullable=False)
    hashed_pwd = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)


#Model need to speak/communicate with the Engine & linking everything together
Base.metadata.create_all(engine)

#Pydantic Models (DataClass)
class UserCreate(BaseModel):
    name:str
    email:str
    role:str
    password:str

#private model response to protect any private information on an app
class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True

#new pydantic models
class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    

#security Fuctions
def verify_pwd(plain_pwd: str, hashed_pwd: str) -> bool:
    return pwd_context.verify(plain_pwd, hashed_pwd)

def get_pwd_hash(pwd: str) -> str:
    return pwd_context.hash(pwd)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str)-> TokenData:
    try:
        payLoad = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payLoad.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"}
                )
        return TokenData(email=email)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
            )

        


#(Function to)get database running
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

#Auth Dependencies
def get_current_user(token:str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    token_data = verify_token(token)
    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"}
            )
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(
            status_code=404, 
            detail="Inactive User",
            )
    return current_user

#Auth endpoints
@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="User already exists",
            )
    hashed_password = get_pwd_hash(user.password)
    db_user = User(
        name=user.name,
        email=user.email,
        role=user.role,
        hashed_pwd=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or not verify_pwd(form_data.password, user.hashed_pwd):
        raise HTTPException(
            status_code=404, 
            detail="Incorrect email or password",
            )
    if not user.is_active:
        raise HTTPException(
            status_code=404, 
            detail="Inactive User",
            )
    
    access_token_expires = timedelta(minutes=TOKEN_EXPIRES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/")
def root():
    return {"message": "Welcome to the User Management API!"}

#endpoint to manage users

#Get user by ID
@app.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int,current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user 


#Create/add new user
@app.post("/users/", response_model=UserResponse)
def create_user(user: UserCreate, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="User already registered")
    
    hashed_password = get_pwd_hash(user.password)
    db_user = User(
        name=user.name,
        email=user.email,
        role=user.role,
        hashed_pwd=hashed_password
    ) 

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return user

#update user information
@app.put("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user: UserCreate, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User does not exist")
    
    db_user.name = user.name
    db_user.email = user.email
    db_user.role = user.role

    db.commit()
    db.refresh(db_user)
    return db_user

#Delete user
@app.delete("/users/{user_id}")
def delete_user(user_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User does not exist")
    
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    
    db.delete(db_user)
    db.commit()
    #db.refresh(db_user)
    return {"message": "User deleted successfully"}

#get profile of the current user endpoint
@app.get("/profile", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/verify-token", response_model=TokenData)
def verify_token(current_user: User = Depends(get_current_active_user)):
    return {
        "valid": True,
        "user": {
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email,
            "role": current_user.role
        }
    }

#get all users
@app.get("/users/", response_model=List[UserResponse])
def get_all_user(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users