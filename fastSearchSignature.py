from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
from collections import OrderedDict
import redis.asyncio as redis
from pydantic import BaseModel, Field
from typing import List

app = FastAPI()

# Redis clients (will be initialized in startup event)
redis_client_white = None
redis_client_malware = None

async def get_redis_clients():
    return (
        redis.Redis(
            host="localhost",
            port=6379,
            db=0,
            password="Maxsecureredis#$2024",
            decode_responses=True
        ),
        redis.Redis(
            host="localhost",
            port=6379,
            db=1,
            password="Maxsecureredis#$2024",
            decode_responses=True
        )
    )

@app.on_event("startup")
async def startup():
    global redis_client_white, redis_client_malware
    redis_client_white, redis_client_malware = await get_redis_clients()

@app.on_event("shutdown")
async def shutdown():
    await redis_client_white.close()
    await redis_client_malware.close()

class SignatureRequest(BaseModel):
    md5: str = Field(..., description="MD5 hash of the file")
    file_signature: str = Field(..., description="File signature")
    file_type: str = Field(..., description="File type")

async def search_in_cache(md5_signature: str, cache_type: str):
    redis_cache = redis_client_white if cache_type == "white" else redis_client_malware
    key_exists = await redis_cache.exists(md5_signature)
    
    if key_exists:
        cache_value = await redis_cache.get(md5_signature)
        if cache_value:
            cache_parts = cache_value.split('|')
            if cache_type == "white":
                return {
                    "Spyware Name": cache_parts[0],
                    "Vendor Name": cache_parts[1],
                    "Source Name": cache_parts[2],
                    "status": 0
                }
            elif cache_type == "malware":
                return {
                    "Spyware Name": cache_parts[0],
                    "Category": cache_parts[2],
                    "status": 1
                }
    
    return {"status": 2}

@app.post("/fastSearchSignature")
async def search_batch(request: Request, signatures: List[SignatureRequest]):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Unauthorized")

    results = []
    current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    for signature in signatures:
        md5_signature = signature.md5.lower()
        
        white_result = await search_in_cache(md5_signature, "white")
        if white_result["status"] == 0:
            results.append(OrderedDict({
                "md5": md5_signature.upper(),
                "date": current_date,
                "file_signature": signature.file_signature,
                "file_type": signature.file_type,
                "is_cache": True,
                "malware_status": 0,
                "threat_name": "WHITE-CLD"
            }))
        else:
            malware_result = await search_in_cache(md5_signature, "malware")
            if malware_result["status"] == 1:
                results.append(OrderedDict({
                    "md5": md5_signature.upper(),
                    "date": current_date,
                    "file_signature": signature.file_signature,
                    "file_type": signature.file_type,
                    "is_cache": True,
                    "malware_status": 1,
                    "threat_name": f"{malware_result.get('Spyware Name', '')}-CLD"
                }))
            else:
                results.append(OrderedDict({
                    "md5": md5_signature.upper(),
                    "date": current_date,
                    "file_signature": signature.file_signature,
                    "file_type": signature.file_type,
                    "is_cache": False,
                    "malware_status": 2,
                    "threat_name": ""
                }))

    if not results:
        raise HTTPException(status_code=400, detail="No Signature Found")

    return JSONResponse(content=results)
