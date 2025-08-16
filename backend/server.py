from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import bcrypt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI(title="Patient-Clinician Health Data Platform", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Models
class UserRole(str):
    PATIENT = "patient"
    CLINICIAN = "clinician"

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str
    license_number: Optional[str] = None  # For clinicians
    specialty: Optional[str] = None  # For clinicians
    date_of_birth: Optional[str] = None  # For patients
    phone: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    role: str
    hashed_password: str
    license_number: Optional[str] = None
    specialty: Optional[str] = None
    date_of_birth: Optional[str] = None
    phone: Optional[str] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    license_number: Optional[str] = None
    specialty: Optional[str] = None
    is_active: bool

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

# Password utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# JWT utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = await db.users.find_one({"id": user_id})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return User(**user)

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def require_role(required_role: str):
    def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {required_role}"
            )
        return current_user
    return role_checker

# Authentication routes
@api_router.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Validate role
    if user_data.role not in [UserRole.PATIENT, UserRole.CLINICIAN]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be 'patient' or 'clinician'"
        )
    
    # Validate clinician requirements
    if user_data.role == UserRole.CLINICIAN:
        if not user_data.license_number or not user_data.specialty:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Clinicians must provide license number and specialty"
            )
    
    # Create user
    hashed_password = get_password_hash(user_data.password)
    user_dict = user_data.dict()
    user_dict.pop('password')
    user_dict['hashed_password'] = hashed_password
    
    user = User(**user_dict)
    await db.users.insert_one(user.dict())
    
    return UserResponse(**user.dict())

@api_router.post("/login", response_model=Token)
async def login(user_credentials: UserLogin):
    user = await db.users.find_one({"email": user_credentials.email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not verify_password(user_credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    access_token = create_access_token(data={"sub": user["id"]})
    user_response = UserResponse(**user)
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=user_response
    )

# Protected routes
@api_router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    return UserResponse(**current_user.dict())

@api_router.get("/dashboard")
async def get_dashboard(current_user: User = Depends(get_current_active_user)):
    if current_user.role == UserRole.PATIENT:
        return {
            "message": f"Welcome to your patient dashboard, {current_user.full_name}!",
            "role": "patient",
            "features": [
                "Upload medical documents",
                "View medical analysis",
                "Connect wearable devices",
                "Generate health reports"
            ]
        }
    else:
        return {
            "message": f"Welcome to your clinician dashboard, Dr. {current_user.full_name}!",
            "role": "clinician",
            "features": [
                "View patient data",
                "Analyze medical documents",
                "Generate clinical reports",
                "Manage patient records"
            ]
        }

# Patient-only routes
@api_router.get("/patient/profile")
async def get_patient_profile(current_user: User = Depends(require_role(UserRole.PATIENT))):
    return {
        "user": UserResponse(**current_user.dict()),
        "health_data": "Patient health data will be displayed here"
    }

# Clinician-only routes
@api_router.get("/clinician/patients")
async def get_patients(current_user: User = Depends(require_role(UserRole.CLINICIAN))):
    return {
        "clinician": UserResponse(**current_user.dict()),
        "patients": "List of patients will be displayed here"
    }

# General API routes
@api_router.get("/")
async def root():
    return {"message": "Patient-Clinician Health Data Platform API"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()