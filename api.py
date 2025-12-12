from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
from datetime import datetime
import base64

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.exceptions import InvalidSignature

app = FastAPI(title="Security Service", version="1.0.0")

KEY_DIR = "keys"
MSG_DIR = "messages"

os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(MSG_DIR, exist_ok=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/store")
async def store_pubkey(username: str = Form(...), file: UploadFile = File(...)):
    data = await file.read()
    save_path = os.path.join(KEY_DIR, f"{username}_pub.pem")
    with open(save_path, "wb") as f:
        f.write(data)
    return {"message": "Public key stored", "user": username}


@app.post("/verify")
async def verify(
    username: str = Form(...),
    message: str = Form(...),
    signature: UploadFile = File(...)
):
    pub_path = os.path.join(KEY_DIR, f"{username}_pub.pem")
    if not os.path.exists(pub_path):
        raise HTTPException(status_code=404, detail="Public key not found for user")

    sig_bytes = await signature.read()
    message_bytes = message.encode()

    # load public key
    with open(pub_path, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())

    try:
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(
                sig_bytes,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return {"status": "valid", "method": "ECDSA", "message": "Signature valid"}

        if isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(sig_bytes, message_bytes)
            return {"status": "valid", "method": "Ed25519", "message": "Signature valid"}

        raise HTTPException(status_code=400, detail="Unsupported public key type")

    except InvalidSignature:
        return {"status": "invalid", "message": "Signature does not match"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification error: {e}")


@app.post("/relay")
async def relay(
    sender: str = Form(...),
    receiver: str = Form(...),
    encrypted_key: str = Form(...),   # base64 or any opaque string produced by client
    ciphertext: str = Form(...),      # base64 ciphertext (AES-GCM)
    nonce: str = Form(...),           # base64 nonce/iv
):
    inbox_path = os.path.join(MSG_DIR, f"{receiver}_inbox.txt")
    timestamp = datetime.now().isoformat()

    with open(inbox_path, "a") as f:
        f.write(f"--- MESSAGE {timestamp} ---\n")
        f.write(f"FROM: {sender}\n")
        f.write(f"encrypted_key: {encrypted_key}\n")
        f.write(f"nonce: {nonce}\n")
        f.write(f"ciphertext: {ciphertext}\n\n")

    return {"message": "Relayed to receiver inbox", "receiver": receiver}


@app.get("/inbox/{user}")
async def inbox(user: str):
    inbox_path = os.path.join(MSG_DIR, f"{user}_inbox.txt")
    if not os.path.exists(inbox_path):
        return {"messages": []}
    with open(inbox_path, "r") as f:
        content = f.read()
    return {"messages_raw": content}
