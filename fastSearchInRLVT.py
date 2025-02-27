import re
from app.services.malicious_urls_services import insert_malicious_url
from config import Config
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
import traceback
import redis.asyncio as redis

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

def check_in_RL_API(url):
    api_url = 'https://data.reversinglabs.com/api/networking/url/v1/report/query/json'
    username = 'u/aura/rlapibundle'
    password = 'Yilk3Wcx'
    payload = {
        "rl": {
            "query": {
                "url": url,
                "response_format": "json"
            }
        }
    }

    try:
        response = requests.post(api_url, json=payload, auth=(username, password), timeout=0.8)
        response.raise_for_status()
        data = response.json()

        # Extract statistics
        statistics = data.get("rl", {}).get("third_party_reputations", {}).get("statistics", {})
        malicious_count = statistics.get("malicious", 0)
        suspicious_count = statistics.get("suspicious", 0)
        classification = data.get("rl", {}).get("classification", "")
        base64_encoded_url = data.get("rl", {}).get("base64", "")

        # print("base64_encoded_url > ", base64_encoded_url)
        return malicious_count + suspicious_count, base64_encoded_url, classification
    except:
        return -1, "", ""
    '''
    except requests.exceptions.Timeout as e:
        print(f"Request timed out RL: {e}")
        return -2, "", ""  # Return empty result in case of timeout

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while making the API call: {e}")
        return 0, "", ""
    except json.JSONDecodeError:
        print("Failed to parse the API response as JSON.")
        return 0, "", ""
    '''

def check_in_VT_API(url, is_base):
    # print("asdasdasd")
    # print("url > ", url)
    if is_base:
        encoded_url = url
    else:
        encoded_url = base64.b64encode(url.encode('utf-8')).decode('utf-8').rstrip("=")

    api_url = 'https://www.virustotal.com/api/v3/urls/' + encoded_url
    # print("API URL > ", api_url)
    api_key = 'ee797f90af81675b63264be149f97fad7a57ae1a9062f16a7096ad3d96072ca3'
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=1.2)
        response.raise_for_status()
        data = response.json()

        # Extract statistics
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        # print("malicious_count > ", malicious_count )
        # print("suspicious_count > ", suspicious_count )
        return malicious_count + suspicious_count
    except:
        return -1
    '''
    except requests.exceptions.Timeout as e:
        print(f"Request timed out VT: {e}")
        return -1
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return -1
    except KeyError as e:
        print(f"Unexpected response structure: {e}")
        return -1
    '''

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


#
# def decode_url(encoded_url, is_base):
#     try:
#         return base64.b64decode(encoded_url).decode('utf-8') if is_base else encoded_url
#     except binascii.Error:
#         raise ValueError("Invalid base64 encoding")
#     except Exception as e:
#         raise ValueError(f"Error decoding URL: {str(e)}")

current_date = datetime.utcnow().date()
RESCAN_COUNTER = int(Config.RESCAN_COUNTER)  # Replace with config
RESCAN_DAYS = int(Config.RESCAN_DAYS)  # Replace with config


@app.get("/fastSearchRLVT")
async def fast_search_malicious_url(request: Request):
    start_time = time.time()  # Start time log
    print(f"API started at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        encoded_url = request.query_params.get('url')
        is_base = request.query_params.get('is_base', 'true').lower() == 'true'

        if not encoded_url:
            total_time = time.time() - start_time  # Total execution time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return JSONResponse({"status": 0, "error": "URL parameter is required"}, status_code=201)

        try:
            url = decode_url(encoded_url, is_base)
        except ValueError as e:
            # traceback.print_exc()
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return JSONResponse({"status": 0, "error": str(e)}, status_code=201)

        md5_hash = get_md5_from_url(url)
        parsed_url = urlparse(url)
        domain_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        md5_domain_url = get_md5_from_url(domain_url)

        # Check Redis Cache
        try:
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
                        print(f"Total Execution Time: {total_time:.4f} seconds")
                        return await handle_cached_result(white_cached_result, source=2)

                    last_value = int(parts[-1])
                    parts[-1] = str(last_value + 1)
                    parts[-2] = datetime.utcnow().strftime('%Y-%m-%d')
                    updated_cache_value = '|'.join(parts)
                    await redis_client_white.set(md5_domain_url, updated_cache_value)
                except Exception as e:
                    traceback.print_exc()
                    total_time = time.time() - start_time
                    print(f"Total Execution Time: {total_time:.4f} seconds")
                    return JSONResponse({"status": 0, "error": f"Error processing cached date: {str(e)}"},
                                        status_code=500)

        except RedisError as e:
            traceback.print_exc()
            print(f"Redis error: {e}")

        # RL API check
        rl_start_time = time.time()
        rl_score, _, classification = check_in_RL_API(url)
        rl_time_taken = time.time() - rl_start_time
        # print(f"RL API Execution Time: {rl_time_taken:.4f} seconds")
        
        if rl_score >= 4:
            insert_malicious_url({"VendorName": "RL", "URL": url, "EntryStatus": 1, "Score": rl_score})
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return JSONResponse({"status": 2, "source": 3, "Vendor": "RL", "Score": rl_score}, status_code=200)
        
        # VT API check
        vt_start_time = time.time()
        vt_score = check_in_VT_API(url, is_base)
        vt_time_taken = time.time() - vt_start_time
        # print(f"VT API Execution Time: {vt_time_taken:.4f} seconds")
        
        if vt_score >= 4:
            insert_malicious_url({"VendorName": "VT", "URL": url, "EntryStatus": 1, "Score": vt_score})
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return JSONResponse({"status": 2, "source": 4, "Vendor": "VT", "Score": vt_score}, status_code=200)
        
        total_time = time.time() - start_time
        print(f"Total Execution Time: {total_time:.4f} seconds")
        return JSONResponse({"status": -1}, status_code=200)

    except Exception as e:
        traceback.print_exc()
        total_time = time.time() - start_time
        print(f"Total Execution Time: {total_time:.4f} seconds")
        return JSONResponse({"status": 0, "error": f"Internal server error: {str(e)}"}, status_code=500)
