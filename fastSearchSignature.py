from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from datetime import datetime
from collections import OrderedDict
import redis.asyncio as redis
from pydantic import BaseModel, Field
from typing import List
import asyncio

app = FastAPI()

# Redis connection setup using FastAPI dependency injection
async def get_redis_client(db: int):
    return await redis.Redis(
        host="localhost",  # Update this with your Redis host
        port=6379,
        db=db,
        password="Maxsecureredis#$2024",
        decode_responses=True
    )

async def get_redis_clients():
    return await asyncio.gather(get_redis_client(0), get_redis_client(1))

redis_client_white, redis_client_malware = asyncio.run(get_redis_clients())

class SignatureRequest(BaseModel):
    md5: str = Field(..., description="MD5 hash of the file")
    file_signature: str = Field(..., description="File signature")
    file_type: str = Field(..., description="File type")

async def search_in_cache(md5_signature: str, cache_type: str):
    client = redis_client_white if cache_type == "white" else redis_client_malware
    return await client.hgetall(md5_signature) or None

@app.post("/fastSearchSignature")
async def search_batch(
    request: Request,
    signatures: List[SignatureRequest]
):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")

    results = []
    current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    async def process_signature(signature: SignatureRequest):
        md5_signature = signature.md5.lower()

        # Perform both searches in parallel
        white_result, malware_result = await asyncio.gather(
            search_in_cache(md5_signature, "white"),
            search_in_cache(md5_signature, "malware")
        )

        if white_result and white_result.get("status") == "0":
            return OrderedDict({
                "md5": md5_signature.upper(),
                "date": current_date,
                "file_signature": signature.file_signature,
                "file_type": signature.file_type,
                "is_cache": True,
                "malware_status": 0,
                "threat_name": "WHITE-CLD"
            })
        elif malware_result and malware_result.get("status") == "1":
            return OrderedDict({
                "md5": md5_signature.upper(),
                "date": current_date,
                "file_signature": signature.file_signature,
                "file_type": signature.file_type,
                "is_cache": True,
                "malware_status": 1,
                "threat_name": f"{malware_result.get('Spyware Name', '')}-CLD"
            })
        else:
            return OrderedDict({
                "md5": md5_signature.upper(),
                "date": current_date,
                "file_signature": signature.file_signature,
                "file_type": signature.file_type,
                "is_cache": False,
                "malware_status": 2,
                "threat_name": ""
            })

    results = await asyncio.gather(*(process_signature(sig) for sig in signatures))

    if not results:
        raise HTTPException(status_code=404, detail="No Signature Found")

    return JSONResponse(content=results)
