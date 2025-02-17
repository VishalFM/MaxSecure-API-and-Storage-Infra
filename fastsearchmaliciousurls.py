from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse
from datetime import datetime
import time
from redis.exceptions import RedisError
from urllib.parse import urlparse
import tldextract
import hashlib
import requests
import base64
import binascii
import re
import traceback
import redis.asyncio as redis
from urllib.parse import urlparse, urlunparse

app = FastAPI()

# Create Redis connection pool
redis_pool = redis.ConnectionPool(
    host="localhost",  # Update this with your Redis host
    port=6379,  # Default Redis port
    db=2,  # Redis database index
    password="Maxsecureredis#$2024",
    decode_responses=True,  # Ensure string decoding
    max_connections=2000  # Connection pool size
)
redis_client_malicious = redis.Redis(connection_pool=redis_pool)

redis_pool_white = redis.ConnectionPool(
    host="localhost",  # Update this with your Redis host
    port=6379,  # Default Redis port
    db=4,  # Redis database index
    password="Maxsecureredis#$2024",
    decode_responses=True,  # Ensure string decoding
    max_connections=2000  # Connection pool size
)
redis_client_white = redis.Redis(connection_pool=redis_pool_white)


def get_md5_from_url(url):
    return hashlib.md5(url.strip().lower().encode('utf-8')).hexdigest()


def extract_main_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain


def get_main_domain(url):
    extracted = tldextract.extract(url)
    main_domain = f"{extracted.domain}.{extracted.suffix}"
    return main_domain


async def handle_cached_result(cached_result, source):
    vendor, score = cached_result.split('|')[2], cached_result.split('|')[1]
    # return JSONResponse({"status": 0 if source == 2 else 2, "source": source, "Vendor": vendor, "Score": score}), 200
    return JSONResponse(
        {"status": 0 if source == 2 else 2, "source": source, "Vendor": vendor, "Score": score},
        status_code=200
    )


def decode_url(encoded_url, is_base):
    # Check if the input URL is Base64 encoded (a common check is whether it matches the Base64 pattern)
    def is_base64(s):
        base64_pattern = r'^[A-Za-z0-9+/=]+$'  # Base64 characters pattern
        return bool(re.match(base64_pattern, s))  # Check if it contains only base64-encoded characters

    if is_base:
        try:
            # Ensure the string matches Base64 format before decoding
            if is_base64(encoded_url):
                # Fix padding if necessary
                missing_padding = len(encoded_url) % 4
                if missing_padding:
                    encoded_url += '=' * (4 - missing_padding)

                return base64.b64decode(encoded_url).decode('utf-8')
            else:
                raise ValueError("The provided URL is not a valid Base64 string")
        except (binascii.Error, ValueError) as e:
            raise ValueError("Invalid base64 encoding") from e
    else:
        return encoded_url


#
# def decode_url(encoded_url, is_base):
#     try:
#         return base64.b64decode(encoded_url).decode('utf-8') if is_base else encoded_url
#     except binascii.Error:
#         raise ValueError("Invalid base64 encoding")
#     except Exception as e:
#         raise ValueError(f"Error decoding URL: {str(e)}")

current_date = datetime.utcnow().date()
RESCAN_COUNTER = 10  # Replace with config
RESCAN_DAYS = 30  # Replace with config


@app.get("/fastSearchMaliciousUrl")
async def fast_search_malicious_url(request: Request):
    start_time = time.time()  # Start time log
    print(f"API started at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        encoded_url = request.query_params.get('url')
        is_base = request.query_params.get('is_base', 'true').lower() == 'true'

        if not encoded_url:
            total_time = time.time() - start_time  # Total execution time
            print(f"{encoded_url} : {total_time:.4f} seconds")
            return JSONResponse({"status": 0, "error": "URL parameter is required"}, status_code=201)

        try:
            url = decode_url(encoded_url, is_base)
        except ValueError as e:
            # traceback.print_exc()
            total_time = time.time() - start_time
            print(f"{encoded_url} : {total_time:.4f} seconds")
            return JSONResponse({"status": 0, "error": str(e)}, status_code=201)

        md5_hash = get_md5_from_url(url)
        parsed_url = urlparse(url)
        domain_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        md5_domain_url = get_md5_from_url(domain_url)

        # Check Redis Cache
        try:
            redis_start_time = time.time()
            maliciours_url_cached_result = await redis_client_malicious.get(md5_hash)
            redis_time_taken = time.time() - redis_start_time
            # print(f"Redis Cache Search Execution Time: {redis_time_taken:.4f} seconds")

            if maliciours_url_cached_result:
                try:
                    total_time = time.time() - start_time
                    print(f"{encoded_url} : {total_time:.4f} seconds")
                    return await handle_cached_result(maliciours_url_cached_result, source=1)
                except Exception as e:
                    traceback.print_exc()
                    print(f"Error - {e} \nIssue in Redis value for key - {md5_hash}")

            redis_start_time = time.time()
            white_cached_result = await redis_client_white.get(md5_domain_url)
            redis_time_taken = time.time() - redis_start_time
            # print(f"Redis White Domain Cache Search Execution Time: {redis_time_taken:.4f} seconds")

            if white_cached_result:
                # Process cached data for white domain
                try:
                    parts = white_cached_result.split('|')
                    cache_date_str = parts[3]
                    cache_counter = int(parts[4])
                    cache_date = datetime.strptime(cache_date_str, '%Y-%m-%d').date()
                    if not (cache_counter < RESCAN_COUNTER and (current_date - cache_date).days > RESCAN_DAYS):
                        total_time = time.time() - start_time
                        print(f"{encoded_url} : {total_time:.4f} seconds")
                        return await handle_cached_result(white_cached_result, source=2)

                    # last_value = int(parts[-1])
                    # parts[-1] = str(last_value + 1)
                    # parts[-2] = datetime.utcnow().strftime('%Y-%m-%d')
                    # updated_cache_value = '|'.join(parts)
                    # await redis_client_white.set(md5_domain_url, updated_cache_value)
                except Exception as e:
                    traceback.print_exc()
                    total_time = time.time() - start_time
                    print(f"{encoded_url} : {total_time:.4f} seconds")
                    return JSONResponse({"status": 0, "error": f"Error processing cached date: {str(e)}"},
                                        status_code=500)

        except RedisError as e:
            traceback.print_exc()
            print(f"Redis error: {e}")

        # # RL API check
        # rl_start_time = time.time()
        # rl_score, _, classification = check_in_RL_API(url)
        # rl_time_taken = time.time() - rl_start_time
        # # print(f"RL API Execution Time: {rl_time_taken:.4f} seconds")
        #
        # if rl_score >= 4:
        #     total_time = time.time() - start_time
        #     print(f"Total Execution Time: {total_time:.4f} seconds")
        #     return JSONResponse({"status": 2, "source": 3, "Vendor": "RL", "Score": rl_score}, status_code=200)
        #
        # # VT API check
        # vt_start_time = time.time()
        # vt_score = check_in_VT_API(url, is_base)
        # vt_time_taken = time.time() - vt_start_time
        # # print(f"VT API Execution Time: {vt_time_taken:.4f} seconds")
        #
        # if vt_score >= 4:
        #     total_time = time.time() - start_time
        #     print(f"Total Execution Time: {total_time:.4f} seconds")
        #     return JSONResponse({"status": 2, "source": 4, "Vendor": "VT", "Score": vt_score}, status_code=200)
        #
        # total_time = time.time() - start_time
        # print(f"Total Execution Time: {total_time:.4f} seconds")
        return JSONResponse({"status": -1}, status_code=200)

    except Exception as e:
        traceback.print_exc()
        total_time = time.time() - start_time
        print(f"{encoded_url} : {total_time:.4f} seconds")
        return JSONResponse({"status": 0, "error": f"Internal server error: {str(e)}"}, status_code=500)


@app.post("/search")
async def search_endpoint(request: Request):
    data = await request.json()
    return {"message": "Search endpoint is working!", "data": data}
