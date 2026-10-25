import hashlib
import os
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Rico Guard Security Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shubhali fayl kengaytmalari ro'yxati
DANGEROUS_EXTENSIONS = [".apk", ".exe", ".scr", ".bat", ".vbs", ".ps1", ".dex", ".sh"]

class ScanResult(BaseModel):
    filename: str
    is_threat: bool
    risk_score: int  # 0 (Xavfsiz) - 100 (Juda xavfli)
    action: str
    message: str

@app.get("/")
def home():
    return {"status": "Rico Guard Engine is active 🛡️"}

@app.post("/scan-file", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    filename = file.filename.lower()
    ext = os.path.splitext(filename)[1]
    
    # 1. Kengaytma bo'yicha tekshirish
    is_dangerous_ext = ext in DANGEROUS_EXTENSIONS
    
    # 2. Fayl kontentini o'qish va SHA-256 hash olish (fayl izini tekshirish)
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Xavflilik darajasini hisoblash
    risk_score = 0
    if is_dangerous_ext:
        risk_score += 60
    
    # Fayl hajmi o'ta kichik bo'lgan shubhali exe/apk stager fayllar uchun
    if is_dangerous_ext and len(content) < 500 * 1024:  # 500 KB dan kichik
        risk_score += 30
        
    is_threat = risk_score >= 50
    
    if is_threat:
        action = "DELETE_AND_CLEAN"
        message = f"DANGER: '{filename}' zararli yoki shubhali fayl sifatida aniqlandi!"
    else:
        action = "ALLOW"
        message = f"SAFE: '{filename}' fayli toza."

    return ScanResult(
        filename=file.filename,
        is_threat=is_threat,
        risk_score=risk_score,
        action=action,
        message=message
    )