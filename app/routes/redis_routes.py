import base64
# import binascii
import binascii
from concurrent.futures import ThreadPoolExecutor
import time
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify
from app.services.RL_VT_API_services import check_in_RL_API, check_in_VT_API
from app.services.malicious_urls_services import insert_malicious_url
from app.services.redis_services import search_in_cache, search_in_malware_cache, search_in_white_cache, RedisService
import threading
from app.utils.parse_url import extract_main_domain, get_main_domain, get_md5_from_url

search_bp = Blueprint('search', __name__)
redis_service = RedisService()

@search_bp.route('/search/<md5_signature>', methods=['GET'])
def search(md5_signature):
    try:
        md5_signature = base64.b64decode(md5_signature).decode('utf-8')
    except Exception as e:
        return jsonify({"status": "error", "message": "Invalid Base64 encoding", "error": str(e)}), 400

    result_dict = {"found_in_white": False, "found_in_malware": False, "status": 2}
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_white = executor.submit(search_in_cache, md5_signature, result_dict, "white")
        future_malware = executor.submit(search_in_cache, md5_signature, result_dict, "malware")
        
        white_result = future_white.result()
        malware_result = future_malware.result()
        if white_result and white_result.get("status") == 0:
            result_dict["found_in_white"] = True
            result_dict["cache_value"] = white_result  # Add cache value for response
        if malware_result and malware_result.get("status") == 1:
            result_dict["found_in_malware"] = True
            result_dict["cache_value"] = malware_result  # Add cache value for response

    if result_dict.get("found_in_white", False):
        return jsonify({"data": result_dict["cache_value"]}), 200
    elif result_dict.get("found_in_malware", False):
        return jsonify({"data": result_dict["cache_value"]}), 200
    else:
        return jsonify({"status": "success", "message": "Not found in either cache"}), 200

@search_bp.route('/searchMaliciousUrl', methods=['GET'])
def search_malicious_url():
    try:
        start_time = time.time()  # Record the start time for the entire function
        function_name = "search_malicious_url"

        encoded_url = request.args.get('url')
        is_base = request.args.get('is_base', default='true', type=str).lower() == 'true'

        print("\n\n\nURL > ", encoded_url)

        if not encoded_url:
            execution_time = time.time() - start_time
            print(f"[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
            return jsonify({"status": 0, "error": "URL parameter is required"}), 400
        
        try:
            if is_base:
                url = base64.b64decode(encoded_url).decode('utf-8')
            else:
                url = encoded_url
        except binascii.Error:
            execution_time = time.time() - start_time
            print(f"[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
            return jsonify({"status": 0, "error": "Invalid base64 encoding"}), 400
        except Exception as e:
            execution_time = time.time() - start_time
            print(f"[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
            return jsonify({"status": 0, "error": f"Error decoding URL: {str(e)}"}), 500

        # Log time for get_md5_from_url
        step_start_time = time.time()
        md5_hash = get_md5_from_url(url)
        print(f"[TIME LOG] get_md5_from_url executed in {time.time() - step_start_time:.4f} seconds")

        # Log time for Redis cache check
        step_start_time = time.time()
        domain_url = urlparse(url).netloc
        md5_domain_url = get_md5_from_url(domain_url)

        print("MD5 of main domain > ", md5_domain_url)
        cached_result = redis_service.search_in_White_main_domain_url_cache(md5_domain_url)
        print(f"[TIME LOG] redis_service.search_in_White_main_domain_url_cache executed in {time.time() - step_start_time:.4f} seconds")

        if cached_result:
            execution_time = time.time() - start_time
            print(f"[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
            vendor, score = cached_result.split('|')[2], cached_result.split('|')[1]
            return jsonify({"status": 0, "source": 1, "Vendor": vendor, "Score": score}), 200
        
        cached_result = redis_service.search_in_malicious_url_cache(md5_hash)
        print(f"[TIME LOG] redis_service.search_in_malicious_url_cache executed in {time.time() - step_start_time:.4f} seconds")

        if cached_result:
            execution_time = time.time() - start_time
            print(f"[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
            vendor, score = cached_result.split('|')[2], cached_result.split('|')[1]
            return jsonify({"status": 2, "source": 1, "Vendor": vendor, "Score": score}), 200

        # Log time for RL API check
        step_start_time = time.time()
        rl_score, base64_encoded_url, classification = check_in_RL_API(url)
        print(f"[TIME LOG] check_in_RL_API executed in {time.time() - step_start_time:.4f} seconds")

        if rl_score >= 4:
            step_start_time = time.time()
            record = {
                "VendorName": "RL",
                "URL": url,
                "EntryStatus": 1,
                "Score": rl_score
            }
            insert_malicious_url(record)
            print(f"[TIME LOG] insert_malicious_url (RL) executed in {time.time() - step_start_time:.4f} seconds")
            execution_time = time.time() - start_time
            print(f"[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
            return jsonify({"status": 2, "source": 3, "Vendor": "RL", "Score": rl_score}), 200
        if classification in ['known'] or rl_score <= 3:
            white_domain_url = urlparse(url).netloc
            md5_white_domain_url = get_md5_from_url(white_domain_url)
            cache_value = f"{0}|{rl_score}|{'RL'}"
            redis_service.bulk_insert_cache([(md5_white_domain_url, cache_value)], "white_main_domain_url")

        # Log time for VT API check
        step_start_time = time.time()
        vt_score = check_in_VT_API(url, False)
        print(f"[TIME LOG] check_in_VT_API executed in {time.time() - step_start_time:.4f} seconds")

        if vt_score >= 4:
            step_start_time = time.time()
            record = {
                "VendorName": "VT",
                "URL": url,
                "EntryStatus": 1,
                "Score": vt_score
            }
            insert_malicious_url(record)
            print(f"[TIME LOG] insert_malicious_url (VT) executed in {time.time() - step_start_time:.4f} seconds")
            execution_time = time.time() - start_time
            print(f"[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
            return jsonify({"status": 2, "source": 4, "Vendor": "VT", "Score": vt_score}), 200
        
        if vt_score <= 3:
            white_domain_url = urlparse(url).netloc
            md5_white_domain_url = get_md5_from_url(white_domain_url)
            cache_value = f"{0}|{vt_score}|{'VT'}"
            redis_service.bulk_insert_cache([(md5_white_domain_url, cache_value)], "white_main_domain_url")

        execution_time = time.time() - start_time
        print(f"[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
        return jsonify({"status": 0}), 200

    except Exception as e:
        execution_time = time.time() - start_time
        print(f"[TIME LOG] {function_name} executed in {execution_time:.4f} seconds")
        return jsonify({"status": 0, "error": f"Internal server error: {str(e)}"}), 500
