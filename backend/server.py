from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, File, UploadFile, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import asyncio
import aiofiles
import json
import tempfile
import io

# Medical analysis and RAG
import requests
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
import chromadb
import pytesseract
from pdf2image import convert_from_path
from PyPDF2 import PdfReader
import cv2
import numpy as np
from PIL import Image

# MinIO for file storage
from minio import Minio
from minio.error import S3Error

# FHIR resources
from fhir.resources.patient import Patient
from fhir.resources.documentreference import DocumentReference
from fhir.resources.observation import Observation

# PDF Report generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# Wearable data APIs
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import fitbit

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configuration
MONGO_URL = os.environ['MONGO_URL']
DB_NAME = os.environ.get('DB_NAME', 'healthsync_platform')
JWT_SECRET = os.environ.get('JWT_SECRET', 'healthsync-jwt-secret-key-change-in-production-2024')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# MinIO Configuration
MINIO_ENDPOINT = os.environ.get('MINIO_ENDPOINT', 'localhost:9000')
MINIO_ACCESS_KEY = os.environ.get('MINIO_ACCESS_KEY', 'minioadmin')
MINIO_SECRET_KEY = os.environ.get('MINIO_SECRET_KEY', 'minioadmin')
MINIO_BUCKET = os.environ.get('MINIO_BUCKET', 'health-documents')

# Google Fit Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:8000/api/wearable/google/callback')

# Fitbit Configuration
FITBIT_CLIENT_ID = os.environ.get('FITBIT_CLIENT_ID')
FITBIT_CLIENT_SECRET = os.environ.get('FITBIT_CLIENT_SECRET')
FITBIT_REDIRECT_URI = os.environ.get('FITBIT_REDIRECT_URI', 'http://localhost:8000/api/wearable/fitbit/callback')

# MongoDB connection
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# MinIO client
minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=False  # Set to True for HTTPS
)

# Create MinIO bucket if it doesn't exist
try:
    if not minio_client.bucket_exists(MINIO_BUCKET):
        minio_client.make_bucket(MINIO_BUCKET)
except S3Error as e:
    logging.error(f"MinIO bucket creation error: {e}")

# Initialize ChromaDB for RAG
chroma_client = chromadb.PersistentClient(path="./medical_vector_db")
try:
    collection = chroma_client.get_collection("medical_documents")
except:
    collection = chroma_client.create_collection("medical_documents")

# Create the main app
app = FastAPI(title="HealthSync - Patient-Clinician Health Data Platform", version="1.0.0")
api_router = APIRouter(prefix="/api")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Models
class UserRole:
    PATIENT = "patient"
    CLINICIAN = "clinician"

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str
    license_number: Optional[str] = None
    specialty: Optional[str] = None
    date_of_birth: Optional[str] = None
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

class DocumentUpload(BaseModel):
    document_id: str
    filename: str
    file_size: int
    content_type: str
    patient_id: Optional[str] = None
    document_type: str = "medical_record"
    upload_status: str = "uploaded"

class MedicalAnalysisRequest(BaseModel):
    query: str
    document_ids: Optional[List[str]] = None
    analysis_type: str = "general"

class MedicalAnalysisResponse(BaseModel):
    analysis_id: str
    query: str
    response: str
    confidence_score: float
    sources: List[str]
    timestamp: str

class WearableDataRequest(BaseModel):
    data_type: str  # steps, heart_rate, sleep, activity
    start_date: str
    end_date: str

class HealthReport(BaseModel):
    report_id: str
    user_id: str
    report_type: str
    date_range: Dict[str, str]
    generated_at: str

# Authentication utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

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
                detail="Could not validate credentials"
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    
    user = await db.users.find_one({"id": user_id})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return User(**user)

# Medical Document Processing
class MedicalDocumentProcessor:
    def __init__(self):
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
    
    async def process_pdf(self, file_path: str) -> Dict[str, Any]:
        """Extract text from PDF with OCR fallback"""
        try:
            # Try direct text extraction first
            text = await self._extract_text_direct(file_path)
            
            if len(text.strip()) < 100:
                # Fallback to OCR
                text = await self._extract_text_ocr(file_path)
            
            # Extract medical entities
            entities = self._extract_medical_entities(text)
            
            return {
                "success": True,
                "text": text,
                "entities": entities,
                "page_count": self._get_page_count(file_path)
            }
        except Exception as e:
            logger.error(f"PDF processing failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _extract_text_direct(self, file_path: str) -> str:
        """Direct text extraction from PDF"""
        text = ""
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PdfReader(file)
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
        except Exception as e:
            logger.error(f"Direct text extraction failed: {e}")
        return text
    
    async def _extract_text_ocr(self, file_path: str) -> str:
        """OCR text extraction from PDF"""
        text = ""
        try:
            images = convert_from_path(file_path, dpi=300)
            for image in images:
                # Preprocess image for better OCR
                processed_image = self._preprocess_image(image)
                page_text = pytesseract.image_to_string(processed_image)
                text += page_text + "\n"
        except Exception as e:
            logger.error(f"OCR extraction failed: {e}")
        return text
    
    def _preprocess_image(self, image: Image.Image) -> Image.Image:
        """Preprocess image for better OCR results"""
        try:
            # Convert to OpenCV format
            opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
            
            # Apply threshold to get image with only black and white
            processed = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
            
            # Convert back to PIL
            return Image.fromarray(processed)
        except Exception as e:
            logger.warning(f"Image preprocessing failed: {e}")
            return image
    
    def _extract_medical_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract medical entities from text"""
        entities = {
            "conditions": [],
            "medications": [],
            "procedures": [],
            "vital_signs": [],
            "lab_values": []
        }
        
        # Simple regex-based extraction (in production, use medical NLP libraries)
        import re
        
        # Extract vital signs
        bp_pattern = r'(?:bp|blood pressure):\s*(\d+/\d+)'
        hr_pattern = r'(?:hr|heart rate):\s*(\d+)'
        temp_pattern = r'(?:temp|temperature):\s*(\d+\.?\d*)'
        
        entities["vital_signs"].extend(re.findall(bp_pattern, text, re.IGNORECASE))
        entities["vital_signs"].extend(re.findall(hr_pattern, text, re.IGNORECASE))
        entities["vital_signs"].extend(re.findall(temp_pattern, text, re.IGNORECASE))
        
        return entities
    
    def _get_page_count(self, file_path: str) -> int:
        """Get number of pages in PDF"""
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PdfReader(file)
                return len(pdf_reader.pages)
        except:
            return 0

    async def add_to_vector_store(self, text: str, document_id: str, metadata: Dict):
        """Add document to vector store for RAG"""
        try:
            # Split text into chunks
            documents = [Document(page_content=text, metadata=metadata)]
            chunks = self.text_splitter.split_documents(documents)
            
            # Add to ChromaDB
            texts = [chunk.page_content for chunk in chunks]
            metadatas = [{"document_id": document_id, **chunk.metadata} for chunk in chunks]
            ids = [f"{document_id}_{i}" for i in range(len(chunks))]
            
            collection.add(
                documents=texts,
                metadatas=metadatas,
                ids=ids
            )
            
            logger.info(f"Added {len(chunks)} chunks to vector store for document {document_id}")
            return True
        except Exception as e:
            logger.error(f"Vector store addition failed: {e}")
            return False

# Medical Analysis Service
class MedicalAnalysisService:
    def __init__(self):
        self.ollama_url = "http://localhost:11434"
    
    async def analyze_query(self, query: str, document_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyze medical query using RAG"""
        try:
            # Search for relevant context
            context_docs = self._search_similar_documents(query, document_ids)
            
            # Generate response using local LLM (Ollama) or fallback
            response = await self._generate_response(query, context_docs)
            
            return {
                "success": True,
                "response": response,
                "confidence": 0.85,  # Placeholder
                "sources": [doc["document_id"] for doc in context_docs]
            }
        except Exception as e:
            logger.error(f"Medical analysis failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _search_similar_documents(self, query: str, document_ids: Optional[List[str]] = None, k: int = 3) -> List[Dict]:
        """Search for similar documents in vector store"""
        try:
            where_filter = {}
            if document_ids:
                where_filter = {"document_id": {"$in": document_ids}}
            
            results = collection.query(
                query_texts=[query],
                n_results=k,
                where=where_filter if where_filter else None,
                include=['documents', 'metadatas']
            )
            
            formatted_results = []
            if results['documents'] and results['documents'][0]:
                for i, (doc, metadata) in enumerate(zip(results['documents'][0], results['metadatas'][0])):
                    formatted_results.append({
                        'content': doc,
                        'document_id': metadata.get('document_id', 'unknown'),
                        'metadata': metadata
                    })
            
            return formatted_results
        except Exception as e:
            logger.error(f"Document search failed: {e}")
            return []
    
    async def _generate_response(self, query: str, context_docs: List[Dict]) -> str:
        """Generate response using LLM"""
        try:
            # Try Ollama first
            context_text = "\n".join([doc['content'] for doc in context_docs[:3]])
            
            prompt = f"""You are a medical AI assistant. Based on the following medical documents, answer the query.

Medical Context:
{context_text}

Query: {query}

Please provide a helpful, accurate response based on the provided medical information. If the information is insufficient, say so clearly."""

            # Try to use Ollama
            try:
                response = requests.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": "llama3.1:8b",
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.1}
                    },
                    timeout=60
                )
                
                if response.status_code == 200:
                    return response.json().get("response", "Unable to generate response")
            except:
                pass
            
            # Fallback response
            return f"Based on the available medical documents, I found {len(context_docs)} relevant sources. However, I'm unable to provide a detailed analysis at this time. Please consult with a healthcare professional for proper medical advice."
            
        except Exception as e:
            logger.error(f"Response generation failed: {e}")
            return "I'm unable to analyze this query at the moment. Please try again later."

# Wearable Data Service
class WearableDataService:
    def __init__(self):
        self.google_scopes = [
            'https://www.googleapis.com/auth/fitness.activity.read',
            'https://www.googleapis.com/auth/fitness.heart_rate.read',
            'https://www.googleapis.com/auth/fitness.sleep.read'
        ]
    
    def get_google_auth_url(self, user_id: str) -> str:
        """Get Google Fit authorization URL"""
        try:
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": GOOGLE_CLIENT_ID,
                        "client_secret": GOOGLE_CLIENT_SECRET,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [GOOGLE_REDIRECT_URI]
                    }
                },
                scopes=self.google_scopes,
                redirect_uri=GOOGLE_REDIRECT_URI
            )
            
            flow.state = user_id  # Pass user_id as state
            auth_url, _ = flow.authorization_url(prompt='consent')
            return auth_url
        except Exception as e:
            logger.error(f"Google auth URL generation failed: {e}")
            raise HTTPException(status_code=500, detail="Failed to generate authorization URL")
    
    def get_fitbit_auth_url(self, user_id: str) -> str:
        """Get Fitbit authorization URL"""
        try:
            # Construct Fitbit OAuth URL
            scopes = ["activity", "heartrate", "sleep", "profile"]
            scope_string = "%20".join(scopes)
            
            auth_url = (
                f"https://www.fitbit.com/oauth2/authorize?"
                f"response_type=code&"
                f"client_id={FITBIT_CLIENT_ID}&"
                f"redirect_uri={FITBIT_REDIRECT_URI}&"
                f"scope={scope_string}&"
                f"state={user_id}"
            )
            
            return auth_url
        except Exception as e:
            logger.error(f"Fitbit auth URL generation failed: {e}")
            raise HTTPException(status_code=500, detail="Failed to generate authorization URL")

# PDF Report Generator
class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
    
    async def generate_health_report(self, user_id: str, report_type: str, data: Dict) -> str:
        """Generate PDF health report"""
        try:
            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
            temp_path = temp_file.name
            temp_file.close()
            
            # Create PDF
            doc = SimpleDocTemplate(temp_path, pagesize=A4)
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.darkblue,
                alignment=1  # Center
            )
            
            story.append(Paragraph(f"Health Report - {report_type.title()}", title_style))
            story.append(Spacer(1, 20))
            
            # User info
            user = await db.users.find_one({"id": user_id})
            if user:
                user_info = [
                    ["Patient Name:", user.get('full_name', 'N/A')],
                    ["Email:", user.get('email', 'N/A')],
                    ["Date of Birth:", user.get('date_of_birth', 'N/A')],
                    ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
                ]
                
                user_table = Table(user_info, colWidths=[2*inch, 3*inch])
                user_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(user_table)
                story.append(Spacer(1, 20))
            
            # Health metrics (placeholder data)
            if report_type == "comprehensive":
                # Add health metrics sections
                story.append(Paragraph("Health Metrics Summary", self.styles['Heading2']))
                story.append(Spacer(1, 12))
                
                metrics_data = [
                    ["Metric", "Value", "Status"],
                    ["Average Heart Rate", "72 bpm", "Normal"],
                    ["Daily Steps", "8,500", "Good"],
                    ["Sleep Duration", "7.2 hours", "Adequate"],
                    ["Blood Pressure", "120/80", "Normal"]
                ]
                
                metrics_table = Table(metrics_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
                metrics_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(metrics_table)
                story.append(Spacer(1, 20))
            
            # Build PDF
            doc.build(story)
            
            return temp_path
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise HTTPException(status_code=500, detail="Failed to generate report")

# Initialize services
doc_processor = MedicalDocumentProcessor()
analysis_service = MedicalAnalysisService()
wearable_service = WearableDataService()
report_generator = ReportGenerator()

# API Routes

# Authentication routes
@api_router.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Validate role
    if user_data.role not in [UserRole.PATIENT, UserRole.CLINICIAN]:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    # Validate clinician requirements
    if user_data.role == UserRole.CLINICIAN:
        if not user_data.license_number or not user_data.specialty:
            raise HTTPException(status_code=400, detail="Clinicians must provide license number and specialty")
    
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
    if not user or not verify_password(user_credentials.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": user["id"]})
    user_response = UserResponse(**user)
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@api_router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return UserResponse(**current_user.dict())

@api_router.get("/dashboard")
async def get_dashboard(current_user: User = Depends(get_current_user)):
    # Get user's documents and recent activity
    documents = await db.documents.find({"user_id": current_user.id}).limit(5).to_list(5)
    analyses = await db.analyses.find({"user_id": current_user.id}).limit(5).to_list(5)
    
    dashboard_data = {
        "user": UserResponse(**current_user.dict()),
        "stats": {
            "total_documents": await db.documents.count_documents({"user_id": current_user.id}),
            "total_analyses": await db.analyses.count_documents({"user_id": current_user.id}),
            "wearable_connected": await db.wearable_tokens.count_documents({"user_id": current_user.id}) > 0
        },
        "recent_documents": [
            {
                "id": doc.get("document_id"),
                "filename": doc.get("filename"),
                "uploaded_at": doc.get("uploaded_at", "").isoformat() if isinstance(doc.get("uploaded_at"), datetime) else doc.get("uploaded_at")
            } for doc in documents
        ],
        "recent_analyses": [
            {
                "id": analysis.get("analysis_id"),
                "query": analysis.get("query", "")[:100] + "..." if len(analysis.get("query", "")) > 100 else analysis.get("query", ""),
                "created_at": analysis.get("created_at", "").isoformat() if isinstance(analysis.get("created_at"), datetime) else analysis.get("created_at")
            } for analysis in analyses
        ]
    }
    
    return dashboard_data

# Document management routes
@api_router.post("/documents/upload")
async def upload_document(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    patient_id: Optional[str] = None,
    document_type: str = "medical_record",
    current_user: User = Depends(get_current_user)
):
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="Only PDF files are supported")
    
    document_id = str(uuid.uuid4())
    
    try:
        # Upload to MinIO
        file_content = await file.read()
        minio_key = f"documents/{document_id}/{file.filename}"
        
        minio_client.put_object(
            MINIO_BUCKET,
            minio_key,
            io.BytesIO(file_content),
            len(file_content),
            content_type=file.content_type
        )
        
        # Store document metadata
        document_data = {
            "document_id": document_id,
            "filename": file.filename,
            "file_size": len(file_content),
            "content_type": file.content_type,
            "minio_key": minio_key,
            "user_id": current_user.id,
            "patient_id": patient_id if patient_id else current_user.id,
            "document_type": document_type,
            "uploaded_at": datetime.utcnow(),
            "processing_status": "pending"
        }
        
        await db.documents.insert_one(document_data)
        
        # Process document in background
        background_tasks.add_task(process_document_background, document_id, file_content)
        
        return DocumentUpload(
            document_id=document_id,
            filename=file.filename,
            file_size=len(file_content),
            content_type=file.content_type,
            patient_id=patient_id,
            document_type=document_type,
            upload_status="uploaded"
        )
        
    except Exception as e:
        logger.error(f"Document upload failed: {e}")
        raise HTTPException(status_code=500, detail="Document upload failed")

async def process_document_background(document_id: str, file_content: bytes):
    """Background task to process uploaded document"""
    try:
        # Update status
        await db.documents.update_one(
            {"document_id": document_id},
            {"$set": {"processing_status": "processing"}}
        )
        
        # Save to temporary file for processing
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
            temp_file.write(file_content)
            temp_path = temp_file.name
        
        # Process document
        result = await doc_processor.process_pdf(temp_path)
        
        if result["success"]:
            # Add to vector store
            document = await db.documents.find_one({"document_id": document_id})
            metadata = {
                "document_id": document_id,
                "filename": document["filename"],
                "document_type": document["document_type"]
            }
            
            await doc_processor.add_to_vector_store(result["text"], document_id, metadata)
            
            # Update document with processing results
            await db.documents.update_one(
                {"document_id": document_id},
                {"$set": {
                    "processing_status": "completed",
                    "extracted_text": result["text"],
                    "medical_entities": result["entities"],
                    "page_count": result["page_count"],
                    "processed_at": datetime.utcnow()
                }}
            )
        else:
            await db.documents.update_one(
                {"document_id": document_id},
                {"$set": {
                    "processing_status": "failed",
                    "error": result.get("error", "Unknown error")
                }}
            )
        
        # Clean up temp file
        os.unlink(temp_path)
        
    except Exception as e:
        logger.error(f"Document processing failed: {e}")
        await db.documents.update_one(
            {"document_id": document_id},
            {"$set": {"processing_status": "failed", "error": str(e)}}
        )

@api_router.get("/documents")
async def list_documents(current_user: User = Depends(get_current_user)):
    documents = await db.documents.find({"user_id": current_user.id}).to_list(100)
    
    # Format documents for response
    formatted_docs = []
    for doc in documents:
        formatted_docs.append({
            "document_id": doc["document_id"],
            "filename": doc["filename"],
            "file_size": doc["file_size"],
            "document_type": doc["document_type"],
            "uploaded_at": doc["uploaded_at"].isoformat() if isinstance(doc["uploaded_at"], datetime) else doc["uploaded_at"],
            "processing_status": doc["processing_status"]
        })
    
    return {"documents": formatted_docs}

@api_router.get("/documents/{document_id}/download")
async def download_document(document_id: str, current_user: User = Depends(get_current_user)):
    document = await db.documents.find_one({"document_id": document_id, "user_id": current_user.id})
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    try:
        # Get file from MinIO
        file_obj = minio_client.get_object(MINIO_BUCKET, document["minio_key"])
        
        def iterfile():
            yield from file_obj
        
        return StreamingResponse(
            iterfile(),
            media_type=document["content_type"],
            headers={"Content-Disposition": f"attachment; filename={document['filename']}"}
        )
    except Exception as e:
        logger.error(f"Document download failed: {e}")
        raise HTTPException(status_code=500, detail="Document download failed")

# Medical analysis routes
@api_router.post("/analyze", response_model=MedicalAnalysisResponse)
async def analyze_medical_query(
    request: MedicalAnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    analysis_id = str(uuid.uuid4())
    
    try:
        # Perform analysis
        result = await analysis_service.analyze_query(request.query, request.document_ids)
        
        if not result["success"]:
            raise HTTPException(status_code=500, detail=result.get("error", "Analysis failed"))
        
        # Store analysis result
        analysis_data = {
            "analysis_id": analysis_id,
            "user_id": current_user.id,
            "query": request.query,
            "response": result["response"],
            "confidence_score": result["confidence"],
            "sources": result["sources"],
            "analysis_type": request.analysis_type,
            "created_at": datetime.utcnow()
        }
        
        await db.analyses.insert_one(analysis_data)
        
        return MedicalAnalysisResponse(
            analysis_id=analysis_id,
            query=request.query,
            response=result["response"],
            confidence_score=result["confidence"],
            sources=result["sources"],
            timestamp=datetime.utcnow().isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Medical analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Analysis failed")

# Wearable data routes
@api_router.get("/wearable/google/auth")
async def google_fit_auth(current_user: User = Depends(get_current_user)):
    """Get Google Fit authorization URL"""
    auth_url = wearable_service.get_google_auth_url(current_user.id)
    return {"auth_url": auth_url}

@api_router.get("/wearable/fitbit/auth")
async def fitbit_auth(current_user: User = Depends(get_current_user)):
    """Get Fitbit authorization URL"""
    auth_url = wearable_service.get_fitbit_auth_url(current_user.id)
    return {"auth_url": auth_url}

@api_router.get("/wearable/google/callback")
async def google_fit_callback(code: str, state: str):
    """Handle Google Fit OAuth callback"""
    try:
        # Exchange code for tokens
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_REDIRECT_URI]
                }
            },
            scopes=wearable_service.google_scopes,
            redirect_uri=GOOGLE_REDIRECT_URI
        )
        
        flow.fetch_token(code=code)
        
        # Store tokens
        token_data = {
            "user_id": state,
            "platform": "google_fit",
            "access_token": flow.credentials.token,
            "refresh_token": flow.credentials.refresh_token,
            "expires_at": flow.credentials.expiry.isoformat() if flow.credentials.expiry else None,
            "created_at": datetime.utcnow()
        }
        
        await db.wearable_tokens.insert_one(token_data)
        
        return {"status": "success", "message": "Google Fit connected successfully"}
        
    except Exception as e:
        logger.error(f"Google Fit callback failed: {e}")
        raise HTTPException(status_code=500, detail="Authorization failed")

@api_router.get("/wearable/fitbit/callback")
async def fitbit_callback(code: str, state: str):
    """Handle Fitbit OAuth callback"""
    try:
        # Exchange code for tokens
        token_response = requests.post(
            "https://api.fitbit.com/oauth2/token",
            data={
                "client_id": FITBIT_CLIENT_ID,
                "grant_type": "authorization_code",
                "redirect_uri": FITBIT_REDIRECT_URI,
                "code": code
            },
            auth=(FITBIT_CLIENT_ID, FITBIT_CLIENT_SECRET)
        )
        
        if token_response.status_code == 200:
            tokens = token_response.json()
            
            # Store tokens
            token_data = {
                "user_id": state,
                "platform": "fitbit",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "expires_at": (datetime.utcnow() + timedelta(seconds=tokens["expires_in"])).isoformat(),
                "created_at": datetime.utcnow()
            }
            
            await db.wearable_tokens.insert_one(token_data)
            
            return {"status": "success", "message": "Fitbit connected successfully"}
        else:
            raise HTTPException(status_code=400, detail="Token exchange failed")
            
    except Exception as e:
        logger.error(f"Fitbit callback failed: {e}")
        raise HTTPException(status_code=500, detail="Authorization failed")

@api_router.get("/wearable/data")
async def get_wearable_data(
    data_type: str,
    start_date: str,
    end_date: str,
    current_user: User = Depends(get_current_user)
):
    """Get wearable data for specified date range"""
    try:
        # Check for connected devices
        tokens = await db.wearable_tokens.find_one({"user_id": current_user.id})
        if not tokens:
            raise HTTPException(status_code=404, detail="No wearable devices connected")
        
        # For now, return mock data
        mock_data = {
            "steps": [
                {"date": "2024-01-01", "value": 8500},
                {"date": "2024-01-02", "value": 9200},
                {"date": "2024-01-03", "value": 7800}
            ],
            "heart_rate": [
                {"date": "2024-01-01", "value": 72},
                {"date": "2024-01-02", "value": 68},
                {"date": "2024-01-03", "value": 75}
            ],
            "sleep": [
                {"date": "2024-01-01", "value": 7.5},
                {"date": "2024-01-02", "value": 8.2},
                {"date": "2024-01-03", "value": 6.8}
            ]
        }
        
        return {
            "data_type": data_type,
            "start_date": start_date,
            "end_date": end_date,
            "data": mock_data.get(data_type, [])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Wearable data retrieval failed: {e}")
        raise HTTPException(status_code=500, detail="Data retrieval failed")

# Report generation routes
@api_router.post("/reports/generate")
async def generate_report(
    report_type: str,
    current_user: User = Depends(get_current_user)
):
    """Generate health report"""
    report_id = str(uuid.uuid4())
    
    try:
        # Generate PDF report
        report_path = await report_generator.generate_health_report(
            current_user.id,
            report_type,
            {}  # Additional data would be passed here
        )
        
        # Upload report to MinIO
        with open(report_path, 'rb') as f:
            report_content = f.read()
        
        minio_key = f"reports/{report_id}/health_report_{report_type}.pdf"
        minio_client.put_object(
            MINIO_BUCKET,
            minio_key,
            io.BytesIO(report_content),
            len(report_content),
            content_type="application/pdf"
        )
        
        # Store report metadata
        report_data = {
            "report_id": report_id,
            "user_id": current_user.id,
            "report_type": report_type,
            "minio_key": minio_key,
            "generated_at": datetime.utcnow(),
            "status": "completed"
        }
        
        await db.reports.insert_one(report_data)
        
        # Clean up temp file
        os.unlink(report_path)
        
        return HealthReport(
            report_id=report_id,
            user_id=current_user.id,
            report_type=report_type,
            date_range={"start": "2024-01-01", "end": "2024-01-31"},
            generated_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail="Report generation failed")

@api_router.get("/reports/{report_id}/download")
async def download_report(report_id: str, current_user: User = Depends(get_current_user)):
    """Download generated report"""
    report = await db.reports.find_one({"report_id": report_id, "user_id": current_user.id})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    try:
        # Get file from MinIO
        file_obj = minio_client.get_object(MINIO_BUCKET, report["minio_key"])
        
        def iterfile():
            yield from file_obj
        
        return StreamingResponse(
            iterfile(),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=health_report_{report['report_type']}.pdf"}
        )
    except Exception as e:
        logger.error(f"Report download failed: {e}")
        raise HTTPException(status_code=500, detail="Report download failed")

# Health check
@api_router.get("/health")
async def health_check():
    """System health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": "connected",
            "minio": "connected" if minio_client else "disconnected",
            "vector_store": "connected" if collection else "disconnected"
        }
    }

# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event
@app.on_event("startup")
async def startup_event():
    logger.info("HealthSync Platform API started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    client.close()
    logger.info("HealthSync Platform API shutdown completed")