from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
import os
from datetime import datetime
from contextlib import contextmanager
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

KEY_DIR = "data/keys"
MSG_DIR = "data/messages"

os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(MSG_DIR, exist_ok=True)



app = FastAPI(title="Security Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def get_index() -> dict:
	return {
		"message": "Hello world! Please visit http://localhost:8080/docs for API UI."
	}


@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    if file.content_type != "application/pdf":
        raise HTTPException(
            status_code=400,
            detail="Only PDF files are allowed"
        )

    try:
        upload_dir = "data/pdfs"
        os.makedirs(upload_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{file.filename}"

        file_path = os.path.join(upload_dir, safe_filename)

        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upload file: {str(e)}"
        )

    return {
        "message": "PDF uploaded successfully",
        "filename": safe_filename,
        "content_type": file.content_type,
        "size_bytes": len(contents)
    }

    

@app.post("/store")
async def store_pubkey(username: str, pubkey: UploadFile = File(...)):
    try:
        content = await pubkey.read()

        serialization.load_pem_public_key(content)

        path = os.path.join(KEY_DIR, f"{username}.pem")
        with open(path, "wb") as f:
            f.write(content)

        msg = "Public key stored successfully"

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "message": msg,
        "user": username
    }

    

@app.post("/verify")
async def verify(
    username: str,
    message: str,
    signature_b64: str
):
    try:
        key_path = os.path.join(KEY_DIR, f"{username}.pem")
        if not os.path.exists(key_path):
            raise HTTPException(status_code=404, detail="Public key not found")

        with open(key_path, "rb") as f:
            pubkey = serialization.load_pem_public_key(f.read())

        signature = base64.b64decode(signature_b64)
        pubkey.verify(signature, message.encode())

        msg = "Signature is VALID"

    except Exception as e:
        msg = "Signature is INVALID"
        raise HTTPException(status_code=400, detail=msg)

    return {
        "message": msg,
        "user": username
    }


@app.post("/relay")
async def relay(
    sender: str,
    receiver: str,
    message: str
):
    try:
        timestamp = datetime.now().isoformat()

        data = {
            "from": sender,
            "to": receiver,
            "message": message,
            "time": timestamp
        }

        fname = f"{receiver}_{int(datetime.now().timestamp())}.txt"
        path = os.path.join(MSG_DIR, fname)

        with open(path, "w") as f:
            f.write(str(data))

        msg = "Message relayed successfully"

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "message": msg,
        "from": sender,
        "to": receiver
    }
