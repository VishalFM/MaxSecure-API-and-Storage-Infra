import base64
import binascii
import re
from pydantic import BaseModel
import asyncpg
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import hashlib
import time
from urllib.parse import urlparse
from datetime import datetime, UTC

app = FastAPI()

# PostgreSQL connection details
PGSQL_HOST = "antivirus-postgres-test-instance-1.cpsi00o0qxrg.us-east-1.rds.amazonaws.com"
PGSQL_PORT = 5432
PGSQL_DB = "antivirusdb"
PGSQL_USER = "antiviruspgsql"
PGSQL_PASSWORD = "Maxsecurepgsql#$2024"

# Create PostgreSQL connection pool
pgsql_pool = None

async def init_pgsql():
    global pgsql_pool
    pgsql_pool = await asyncpg.create_pool(
        host=PGSQL_HOST,
        port=PGSQL_PORT,
        database=PGSQL_DB,
        user=PGSQL_USER,
        password=PGSQL_PASSWORD
    )

@app.on_event("startup")
async def startup_event():
    await init_pgsql()

@app.on_event("shutdown")
async def shutdown_event():
    await pgsql_pool.close()

def get_md5_from_url(url):
    return hashlib.md5(url.strip().lower().encode('utf-8')).hexdigest()

async def fetch_from_pgsql(md5_hash):
    async with pgsql_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT	\"EntryStatus\" as \"status\",\"VendorID\" as \"source\",\"Name\" as \"Vendor\",\"Score\" as \"Score\" FROM public.\"MaliciousURLs\"  INNER JOIN public.\"Source\"  ON \"VendorID\" = \"Source\".\"ID\"		where \"MD5\"='" + md5_hash + "' LIMIT 1",
            )
        return row  # Returns a row if found, otherwise None

def decode_url(encoded_url, is_base):
    if is_base:
        # Validate if the URL contains Base64-like structure
        if re.match(r'^[A-Za-z0-9+/=]+$', encoded_url):  # Match valid Base64 characters
            try:
                # Fix padding if necessary
                missing_padding = len(encoded_url) % 4
                if missing_padding:
                    encoded_url += '=' * (4 - missing_padding)

                # Attempt Base64 decoding
                return base64.b64decode(encoded_url).decode('utf-8')
            except (binascii.Error, ValueError) as e:
                raise ValueError("The provided URL is not a valid Base64 string") from e
    return encoded_url

class MaliciousUrlRequest(BaseModel):
    url: str
    is_base: bool = False
    
@app.post("/DBSearchMaliciousUrl")
async def DB_fast_search_malicious_url(request_data: MaliciousUrlRequest):
    start_time = time.time()

    try:
        encoded_url = request_data.url
        is_base = request_data.is_base

        if not encoded_url:
            return JSONResponse({"status": 0, "error": "URL parameter is required"}, status_code=201)

        try:
            url = decode_url(encoded_url, is_base)
        except ValueError as e:
            return JSONResponse({"status": 0, "error": str(e)}, status_code=201)

        md5_hash = get_md5_from_url(url)

        # **Step 1: Check PostgreSQL first**
        pgsql_result = await fetch_from_pgsql(md5_hash)
        if pgsql_result:
            total_time = time.time() - start_time
            print(f"{encoded_url} : {total_time:.4f} seconds (From PGSQL)")
            return JSONResponse({
                "status": pgsql_result["status"],
                "source": pgsql_result["source"],
                "Vendor": pgsql_result["Vendor"],
                "Score": pgsql_result["Score"]
            }, status_code=200)

        # **Step 2: Check Redis Cache if not found in PostgreSQL**
      #  try:
       #     maliciours_url_cached_result = await redis_client_malicious.get(md5_hash)
        #    if maliciours_url_cached_result:
         #       vendor, score = maliciours_url_cached_result.split('|')[2], maliciours_url_cached_result.split('|')[1]
          #      return await handle_cached_result(maliciours_url_cached_result, source=1)
        #except RedisError as e:
         #   print(f"Redis error: {e}")

    except Exception as e:
        return JSONResponse({"status": 0, "error": f"Internal server error: {str(e)}"}, status_code=500)
