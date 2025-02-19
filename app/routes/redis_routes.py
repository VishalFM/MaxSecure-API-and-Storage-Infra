import base64
# import binascii
import binascii
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import time
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify
from app.services.RL_VT_API_services import check_in_RL_API, check_in_VT_API
from app.services.malicious_urls_services import insert_malicious_url
from app.services.redis_services import search_in_cache, search_in_malware_cache, search_in_white_cache, RedisService
import threading
from app.services.white_main_domain import insert_white_main_domain_url
from app.utils.parse_url import extract_main_domain, get_main_domain, get_md5_from_url
from config import Config
from collections import OrderedDict
from fastapi import FastAPI
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

search_bp = Blueprint('search', __name__)
redis_service = RedisService()
app = FastAPI()

@search_bp.route('/search', methods=['POST'])
def search_batch():
    try:
         # Extract Authorization header
        auth_header = request.headers.get('Authorization')
        
        if auth_header is None:
            return jsonify({"message": "unauthorized"}), 400
        
        # Check if the header is in the format "Bearer <token>"
        if not auth_header.startswith('Bearer '):
            return jsonify({"message": "unauthorized"}), 400
        
        # Extract the token part (after "Bearer ")
        token = auth_header.split(' ')[1]

        request_data = request.get_json()

        # Ensure that the input is a list of dictionaries
        if not request_data or not isinstance(request_data, list):
            return jsonify({"status": "error", "message": "The request body must be a list of dictionaries"}), 400

        # Query Redis for batch processing
        results = []

        for signature in request_data:
            md5_signature = signature.get('md5').lower()
            file_signature = signature.get('file_signature')
            file_type = signature.get('file_type')

            # Validate required fields
            if not md5_signature or not file_signature or not file_type:
                return jsonify({"status": "error", "message": "Each item must include 'md5', 'file_signature', and 'file_type'"}), 400

            # Query Redis for white and malware results
            white_result = search_in_cache(md5_signature, {}, "white")

            # Current timestamp for the "date" field
            current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

            # If the signature is found in the "white" cache
            if white_result and white_result.get("status") == 0:
                results.append(OrderedDict({
                    "md5": md5_signature.upper(),
                    "date": current_date,
                    "file_signature": file_signature,
                    "file_type": file_type,
                    "is_cache": True,
                    "malware_status": 0,
                    "threat_name": "WHITE-CLD"
                }))
            
            else:
                # Query the malware cache if not found in white cache
                malware_result = search_in_cache(md5_signature, {}, "malware")

                # If the signature is found in the "malware" cache
                if malware_result and malware_result.get("status") == 1:
                    results.append(OrderedDict({
                        "md5": md5_signature.upper(),
                        "date": current_date,
                        "file_signature": file_signature,
                        "file_type": file_type,
                        "is_cache": True,
                        "malware_status": 1,
                        "threat_name": malware_result.get("Spyware Name", "") + "-CLD"
                    }))
                else:
                    results.append(OrderedDict({
                        "md5": md5_signature.upper(),
                        "date": current_date,
                        "file_signature": file_signature,
                        "file_type": file_type,
                        "is_cache": False,
                        "malware_status": 2,
                        "threat_name": ""
                    }))

        
        # If no results found for all signatures
        if not results:
            return jsonify({"message": "No Signature Found"}), 400
        
        # Return the collected results
        return jsonify(results)

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def decode_url(encoded_url, is_base):
    try:
        return base64.b64decode(encoded_url).decode('utf-8') if is_base else encoded_url
    except binascii.Error:
        raise ValueError("Invalid base64 encoding")
    except Exception as e:
        raise ValueError(f"Error decoding URL: {str(e)}")

def cache_insert_white_domain(url, score, vendor):
    parsed_url = urlparse(url)
    white_domain_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    md5_white_domain_url = get_md5_from_url(white_domain_url)
    current_date = datetime.utcnow().strftime('%Y-%m-%d')
    cache_value = f"0|{score}|{vendor}|{current_date}|0"
    redis_service.bulk_insert_cache([(md5_white_domain_url, cache_value)], "white_main_domain_url")
    print("inserted in cache ...")
    return white_domain_url, md5_white_domain_url

def handle_cached_result(cached_result, source):
    vendor, score = cached_result.split('|')[2], cached_result.split('|')[1]
    return jsonify({"status": 0 if source == 2 else 2, "source": source, "Vendor": vendor, "Score": score}), 200

def verify_jwt(token: str, public_key: str, algorithms=['RS256']):
    try:
        decoded_token = jwt.decode(token, public_key, algorithms=algorithms)
        print("JWT is valid.")
        return decoded_token
    except ExpiredSignatureError:
        print("JWT has expired.")
    except InvalidTokenError:
        print("JWT is invalid.")
    return None

# Example usage
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArwrUNz1SYfuusvyKrXE6
zk6lHq8bhJvDQLcHbtQ838bogBnY27bQJ64QXiJN0ZgGJ7+4eyg8tgZ/4k4iYjUn
OarEDKkuYjUpOX/z9TXrmkX+rv/khRJ5iCh5YTH+uXGanJr4xhOsPH9PTOFKiOyh
DKroxHkhpUF0odNeO3pdPXyj1MgUicG0JgWDvYSY0ta2+56z9Vm4YAaehLTCd8yo
58tBvguBqXQNN+fQtG+6J6+nAOZm+1Pve59OrkF9Jm3stFlp6kBU3GsXvvMHsjET
qdnXPxtgSIyle94vee/PXpHE9h6Vw+ok3Q8e9ddE+BzhD4bpyxvlxd6zm40oJdHx
pwIDAQAB
-----END PUBLIC KEY-----"""

# token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlZmF1bHQifQ.eyJpYXQiOjE3MzkyNzgxNzUsIm5iZiI6MTczOTI3ODE3NSwiZXhwIjoxNzM5Mjc4NDc1LCJzdWIiOiI2ZTA2ZGMxMC03NjBjLTRjMDgtODQ2NC02MWM0ZDhkMmY0NmEiLCJqdGkiOiI5N2NlMjY5OS0xMzA5LTQ5MmItODg0Mi1hZGRmYzg1NTg5NjAiLCJhbGlhcyI6InVhdi1xYS0wMTBAYW5jaG9yZnJlZS5jb20iLCJhZ2VudCI6eyJhcGlfa2V5IjoidWx0cmF2cG5fYmFja2VuZCIsInVzZXJfYWdlbnQiOiJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCA1LjE7IHJ2OjMxLjApIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS80NC4wLjI0MDMuODkgU2FmYXJpLzUzNy4zNiIsInJvbGVfbmFtZSI6InVsdHJhdnBuOmJhY2tlbmQiLCJpcCI6IjU0LjIxNS4yMjQuNjMiLCJpc19tYXNxdWVyYWRlIjp0cnVlfSwiYXVyYXN2YzpzZXNzaW9uX2lkIjoiOWJkNzI4NWItZDgzNi00MDgyLWEyNDAtMjQ3NWY0MzBiM2NmIiwiYXVyYXN2YzpkaXJlY3Rvcnlfa2V5IjoidWx0cmF2cG4iLCJhdXJhc3ZjOmVudGl0bGVtZW50cyI6eyJ2cG46ZGV2aWNlX2xpbWl0IjoxMCwiaXRwczpkYXJrX3dlYl9zY2FucyI6MjAwMDAwMCwiYXY6c2Nhbl90eXBlcyI6WyJzbWFydCIsImZ1bGwiLCJjdXN0b20iXSwiYXY6ZmVhdHVyZXMiOlsib25fYWNjZXNzIiwic2NoZWR1bGVkIiwib25fZGVtYW5kIiwiZ2FtZV9tb2RlIl0sImF2OmRldmljZV9saW1pdCI6MjB9LCJhdXJhc3ZjOnJvbGUiOiJ1bHRyYXZwbjpzZXNzaW9uIn0.OO82HjGFOaD6KnFd1CtSijklcqpxrf3zA_9u9rtoytnBxaLrCh4Rw4UqCGSZk8c0DK1sMMQo4LfQPC_ZMac-IS1VNA1KcvXBAFfGzaDjFxfUdf8lWBzc8HcfE1DPoQDyi8eInL7mb8LV_48d_A4WTJu9oNSfiY2dMOyOrqRJSiHF-pvh4BuzifIS-YogGDzUyjhVGukLPr8WQhq6XcFqn5zIAVQRtr6ajEg0pPZW6Boy0DAXunKIW8lBPM5WE7jlHTJNe-UDitKGMTrL30B5TfXH-rvBv7kvCtLH6hpxqtIo1o5RQYGjMnU2KrBbrc7AsRh-43ohwBK7EAse9dZ2cg"

@search_bp.route('/searchMaliciousUrl', methods=['GET'])
def search_malicious_url():
    start_time = time.time()  # Start time log
    print(f"API started at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"status": 0, "error": "Unauthorized"}), 401

        token = auth_header.split(" ")[1]  # Extract token after "Bearer "
        verified_data = verify_jwt(token, public_key)

        # If verification fails, return the error response
        if isinstance(verified_data, tuple):
            return jsonify(verified_data[0]), verified_data[1]

        encoded_url = request.args.get('url')
        is_base = request.args.get('is_base', default='true', type=str).lower() == 'true'

        if not encoded_url:
            total_time = time.time() - start_time  # Total execution time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 0, "error": "URL parameter is required"}), 400

        try:
            url = decode_url(encoded_url, is_base)
        except ValueError as e:
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 0, "error": str(e)}), 400

        md5_hash = get_md5_from_url(url)
        parsed_url = urlparse(url)
        domain_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        md5_domain_url = get_md5_from_url(domain_url)

        # Check Redis Cache
        redis_start_time = time.time()
        cached_result = redis_service.search_in_malicious_url_cache(md5_hash)
        redis_time_taken = time.time() - redis_start_time
        print(f"Redis Cache Search Execution Time: {redis_time_taken:.4f} seconds")

        if cached_result:
            try:
                total_time = time.time() - start_time
                print(f"Total Execution Time: {total_time:.4f} seconds")
                return handle_cached_result(cached_result, source=1)
            except Exception as e:
                print(f"Error - {e} \nIssue in Redis value for key - {md5_hash}")

        redis_start_time = time.time()
        cached_result = redis_service.search_in_White_main_domain_url_cache(md5_domain_url)
        redis_time_taken = time.time() - redis_start_time
        print(f"Redis White Domain Cache Search Execution Time: {redis_time_taken:.4f} seconds")

        if cached_result:
            try:
                parts = cached_result.split('|')
                cache_date_str = parts[3]
                cache_counter = int(parts[4])
                cache_date = datetime.strptime(cache_date_str, '%Y-%m-%d').date()
                current_date = datetime.utcnow().date()
                RESCAN_COUNTER = int(Config.RESCAN_COUNTER)
                RESCAN_DAYS = int(Config.RESCAN_DAYS)
                if not (cache_counter < RESCAN_COUNTER and (current_date - cache_date).days > RESCAN_DAYS):
                    total_time = time.time() - start_time
                    print(f"Total Execution Time: {total_time:.4f} seconds")
                    return handle_cached_result(cached_result, source=2)

                last_value = int(parts[-1])  
                parts[-1] = str(last_value + 1)  
                parts[-2] = datetime.utcnow().strftime('%Y-%m-%d')
                updated_cache_value = '|'.join(parts)
                redis_service.update_cache(md5_domain_url, updated_cache_value, "white_main_domain_url")
            except Exception as e:
                total_time = time.time() - start_time
                print(f"Total Execution Time: {total_time:.4f} seconds")
                return jsonify({"status": 0, "error": f"Error processing cached date: {str(e)}"}), 500

        # RL API check
        rl_start_time = time.time()
        rl_score, _, classification = check_in_RL_API(url)
        rl_time_taken = time.time() - rl_start_time
        print(f"RL API Execution Time: {rl_time_taken:.4f} seconds")

        if rl_score >= 4:
            insert_malicious_url({"VendorName": "RL", "URL": url, "EntryStatus": 1, "Score": rl_score})
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 2, "source": 3, "Vendor": "RL", "Score": rl_score}), 200

        if classification in ['known'] and rl_score == 0:
            white_domain_url, md5_white_domain_url = cache_insert_white_domain(url, rl_score, "RL")
            insert_white_main_domain_url({
                'URL': white_domain_url,
                'MD5': md5_white_domain_url,
                'EntryStatus': 0,
                'Vendor': "RL",
                'counter': 0
            })
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 0, "source": 3, "Vendor": "RL", "Score": rl_score}), 200

        # VT API check
        vt_start_time = time.time()
        vt_score = check_in_VT_API(url, False)
        vt_time_taken = time.time() - vt_start_time
        print(f"VT API Execution Time: {vt_time_taken:.4f} seconds")

        if vt_score >= 4:
            insert_malicious_url({"VendorName": "VT", "URL": url, "EntryStatus": 1, "Score": vt_score})
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 2, "source": 4, "Vendor": "VT", "Score": vt_score}), 200

        if vt_score != -1:
            white_domain_url, md5_white_domain_url = cache_insert_white_domain(url, vt_score, "VT")
            insert_white_main_domain_url({
                'URL': white_domain_url,
                'MD5': md5_white_domain_url,
                'EntryStatus': 0,
                'Vendor': "VT",
                'counter': 0
            })
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 0, "source": 4, "Vendor": "VT", "Score": vt_score}), 200

        total_time = time.time() - start_time
        print(f"Total Execution Time: {total_time:.4f} seconds")
        return jsonify({"status": -1}), 200

    except Exception as e:
        total_time = time.time() - start_time
        print(f"Total Execution Time: {total_time:.4f} seconds")
        return jsonify({"status": 0, "error": f"Internal server error: {str(e)}"}), 500


@app.get("/fastSearchMaliciousUrl")
def fast_searchMaliciousUrl():
    start_time = time.time()  # Start time log
    print(f"API started at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        encoded_url = request.args.get('url')
        is_base = request.args.get('is_base', default='true', type=str).lower() == 'true'

        if not encoded_url:
            total_time = time.time() - start_time  # Total execution time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 0, "error": "URL parameter is required"}), 400

        try:
            url = decode_url(encoded_url, is_base)
        except ValueError as e:
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 0, "error": str(e)}), 400

        md5_hash = get_md5_from_url(url)
        parsed_url = urlparse(url)
        domain_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        md5_domain_url = get_md5_from_url(domain_url)

        # Check Redis Cache
        redis_start_time = time.time()
        cached_result = redis_service.search_in_malicious_url_cache(md5_hash)
        redis_time_taken = time.time() - redis_start_time
        print(f"Redis Cache Search Execution Time: {redis_time_taken:.4f} seconds")

        if cached_result:
            try:
                total_time = time.time() - start_time
                print(f"Total Execution Time: {total_time:.4f} seconds")
                return handle_cached_result(cached_result, source=1)
            except Exception as e:
                print(f"Error - {e} \nIssue in Redis value for key - {md5_hash}")

        redis_start_time = time.time()
        cached_result = redis_service.search_in_White_main_domain_url_cache(md5_domain_url)
        redis_time_taken = time.time() - redis_start_time
        print(f"Redis White Domain Cache Search Execution Time: {redis_time_taken:.4f} seconds")

        if cached_result:
            try:
                parts = cached_result.split('|')
                cache_date_str = parts[3]
                cache_counter = int(parts[4])
                cache_date = datetime.strptime(cache_date_str, '%Y-%m-%d').date()
                current_date = datetime.utcnow().date()
                RESCAN_COUNTER = int(Config.RESCAN_COUNTER)
                RESCAN_DAYS = int(Config.RESCAN_DAYS)
                if not (cache_counter < RESCAN_COUNTER and (current_date - cache_date).days > RESCAN_DAYS):
                    total_time = time.time() - start_time
                    print(f"Total Execution Time: {total_time:.4f} seconds")
                    return handle_cached_result(cached_result, source=2)

                last_value = int(parts[-1])
                parts[-1] = str(last_value + 1)
                parts[-2] = datetime.utcnow().strftime('%Y-%m-%d')
                updated_cache_value = '|'.join(parts)
                redis_service.update_cache(md5_domain_url, updated_cache_value, "white_main_domain_url")
            except Exception as e:
                total_time = time.time() - start_time
                print(f"Total Execution Time: {total_time:.4f} seconds")
                return jsonify({"status": 0, "error": f"Error processing cached date: {str(e)}"}), 500

        # RL API check
        rl_start_time = time.time()
        rl_score, _, classification = check_in_RL_API(url)
        rl_time_taken = time.time() - rl_start_time
        print(f"RL API Execution Time: {rl_time_taken:.4f} seconds")

        if rl_score >= 4:
            insert_malicious_url({"VendorName": "RL", "URL": url, "EntryStatus": 1, "Score": rl_score})
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 2, "source": 3, "Vendor": "RL", "Score": rl_score}), 200

        if classification in ['known'] and rl_score == 0:
            white_domain_url, md5_white_domain_url = cache_insert_white_domain(url, rl_score, "RL")
            insert_white_main_domain_url({
                'URL': white_domain_url,
                'MD5': md5_white_domain_url,
                'EntryStatus': 0,
                'Vendor': "RL",
                'counter': 0
            })
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 0, "source": 3, "Vendor": "RL", "Score": rl_score}), 200

        # VT API check
        vt_start_time = time.time()
        vt_score = check_in_VT_API(url, False)
        vt_time_taken = time.time() - vt_start_time
        print(f"VT API Execution Time: {vt_time_taken:.4f} seconds")

        if vt_score >= 4:
            insert_malicious_url({"VendorName": "VT", "URL": url, "EntryStatus": 1, "Score": vt_score})
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 2, "source": 4, "Vendor": "VT", "Score": vt_score}), 200

        if vt_score != -1:
            white_domain_url, md5_white_domain_url = cache_insert_white_domain(url, vt_score, "VT")
            insert_white_main_domain_url({
                'URL': white_domain_url,
                'MD5': md5_white_domain_url,
                'EntryStatus': 0,
                'Vendor': "VT",
                'counter': 0
            })
            total_time = time.time() - start_time
            print(f"Total Execution Time: {total_time:.4f} seconds")
            return jsonify({"status": 0, "source": 4, "Vendor": "VT", "Score": vt_score}), 200

        total_time = time.time() - start_time
        print(f"Total Execution Time: {total_time:.4f} seconds")
        return jsonify({"status": -1}), 200

    except Exception as e:
        total_time = time.time() - start_time
        print(f"Total Execution Time: {total_time:.4f} seconds")
        return jsonify({"status": 0, "error": f"Internal server error: {str(e)}"}), 500

# def search_malicious_url():
#     try:
#         start_time = time.time()  # Record the start time for the entire function
#         function_name = "search_malicious_url"

#         encoded_url = request.args.get('url')
#         is_base = request.args.get('is_base', default='true', type=str).lower() == 'true'

#         print("\n\n\nURL > ", encoded_url)

#         if not encoded_url:
#             execution_time = time.time() - start_time
#             # print\(f"\[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
#             return jsonify({"status": 0, "error": "URL parameter is required"}), 400
        
#         try:
#             if is_base:
#                 url = base64.b64decode(encoded_url).decode('utf-8')
#             else:
#                 url = encoded_url
#         except binascii.Error:
#             execution_time = time.time() - start_time
#             # print\(f"\[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
#             return jsonify({"status": 0, "error": "Invalid base64 encoding"}), 400
#         except Exception as e:
#             execution_time = time.time() - start_time
#             # print\(f"\[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
#             return jsonify({"status": 0, "error": f"Error decoding URL: {str(e)}"}), 500

#         # Log time for get_md5_from_url
#         step_start_time = time.time()
#         md5_hash = get_md5_from_url(url)
#         # print\(f"\[TIME LOG] get_md5_from_url executed in {time.time() - step_start_time:.4f} seconds")

#         # Log time for Redis cache check
#         step_start_time = time.time()
#         parsed_url = urlparse(url)   
#         domain_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
#         print("domain_url > ", domain_url)
#         md5_domain_url = get_md5_from_url(domain_url)

        
#         cached_result = redis_service.search_in_malicious_url_cache(md5_hash)
#         # print\(f"\[TIME LOG] redis_service.search_in_malicious_url_cache executed in {time.time() - step_start_time:.4f} seconds")

#         if cached_result:
#             execution_time = time.time() - start_time
#             # print\(f"\[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
#             vendor, score = cached_result.split('|')[2], cached_result.split('|')[1]
#             return jsonify({"status": 2, "source": 1, "Vendor": vendor, "Score": score}), 200
        
#         print("MD5 of main domain > ", md5_domain_url)
#         cached_result = redis_service.search_in_White_main_domain_url_cache(md5_domain_url)
#         # print\(f"\[TIME LOG] redis_service.search_in_White_main_domain_url_cache executed in {time.time() - step_start_time:.4f} seconds")

#         if cached_result:
#             execution_time = time.time() - start_time
#             # print\(f"\[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
#             vendor, score = cached_result.split('|')[2], cached_result.split('|')[1]
#             return jsonify({"status": 0, "source": 2, "Vendor": vendor, "Score": score}), 200

#         # Log time for RL API check
#         step_start_time = time.time()
#         rl_score, base64_encoded_url, classification = check_in_RL_API(url)
#         # print\(f"\[TIME LOG] check_in_RL_API executed in {time.time() - step_start_time:.4f} seconds")

#         if rl_score >= 4:
#             step_start_time = time.time()
#             record = {
#                 "VendorName": "RL",
#                 "URL": url,
#                 "EntryStatus": 1,
#                 "Score": rl_score
#             }
#             insert_malicious_url(record)
#             # print\(f"\[TIME LOG] insert_malicious_url (RL) executed in {time.time() - step_start_time:.4f} seconds")
#             execution_time = time.time() - start_time
#             # print\(f"\[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
#             return jsonify({"status": 2, "source": 3, "Vendor": "RL", "Score": rl_score}), 200
#         if (classification in ['known'] and rl_score == 0):
#             parsed_url = urlparse(url)   
#             white_domain_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
#             md5_white_domain_url = get_md5_from_url(white_domain_url)
#             current_date = datetime.utcnow().strftime('%Y-%m-%d')  # Get current UTC date
#             cache_value = f"{0}|{rl_score}|{'RL'}|{current_date}|{0}"  # Add date and counter
#             redis_service.bulk_insert_cache([(md5_white_domain_url, cache_value)], "white_main_domain_url")
#             return jsonify({"status": 0, "source": 3, "Vendor": "RL", "Score": rl_score}), 200
#         else:
#             # Log time for VT API check
#             step_start_time = time.time()
#             vt_score = check_in_VT_API(url, False)
#             # print\(f"\[TIME LOG] check_in_VT_API executed in {time.time() - step_start_time:.4f} seconds")

#             if vt_score >= 4:
#                 step_start_time = time.time()
#                 record = {
#                     "VendorName": "VT",
#                     "URL": url,
#                     "EntryStatus": 1,
#                     "Score": vt_score
#                 }
#                 insert_malicious_url(record)
#                 # print\(f"\[TIME LOG] insert_malicious_url (VT) executed in {time.time() - step_start_time:.4f} seconds")
#                 execution_time = time.time() - start_time
#                 # print\(f"\[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
#                 return jsonify({"status": 2, "source": 4, "Vendor": "VT", "Score": vt_score}), 200
            
#             else:
#                 if vt_score != -1:
#                     white_domain_url = urlparse(url).netloc
#                     md5_white_domain_url = get_md5_from_url(white_domain_url)
#                     current_date = datetime.utcnow().strftime('%Y-%m-%d')  # Get current UTC date
#                     cache_value = f"{0}|{vt_score}|{'VT'}|{current_date}|{0}"  # Add date and counter
#                     redis_service.bulk_insert_cache([(md5_white_domain_url, cache_value)], "white_main_domain_url")
#                     insert_white_main_domain_url({
#                         'URL': white_domain_url,
#                         'MD5': md5_white_domain_url,
#                         'EntryStatus': 0,
#                         'Vendor': "VT",
#                         'counter': 0
#                     })
#                     return jsonify({"status": 0, "source": 4, "Vendor": "VT", "Score": vt_score}), 200

#             execution_time = time.time() - start_time
#             # print\(f"\[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
#             return jsonify({"status": -1}), 200

#     except Exception as e:
#         execution_time = time.time() - start_time
#         # print\(f"\[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
#         return jsonify({"status": 0, "error": f"Internal server error: {str(e)}"}), 500
