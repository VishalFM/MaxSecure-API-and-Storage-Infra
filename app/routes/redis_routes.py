import base64
# import binascii
import binascii
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, request, jsonify
from app.services.RL_VT_API_services import check_in_RL_API, check_in_VT_API
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
        encoded_url = request.args.get('url')
        is_base = request.args.get('is_base', default='true', type=str).lower() == 'true'

        if not encoded_url:
            return jsonify({"status": 0, "error": "URL parameter is required"}), 400
        try:
            if is_base:
                url = base64.b64decode(encoded_url).decode('utf-8')
            else:
                url = encoded_url
        except binascii.Error:
            return jsonify({"status": 0, "error": "Invalid base64 encoding"}), 400
        except Exception as e:
            return jsonify({"status": 0, "error": f"Error decoding URL: {str(e)}"}), 500

        md5_hash = get_md5_from_url(url)
        print("url > ", url)
        print("md5 > ",md5_hash)
        cached_result = redis_service.search_in_malicious_url_cache(md5_hash)
        if cached_result:
            vendor, score = cached_result.split('|')[2], cached_result.split('|')[1]
            if float(score) > 0.4:
                return jsonify({"status": 2, "source": 1, "Vendor": vendor, "Score": score}), 200 
            else:
                return jsonify({"status": 0}), 200 

        classification, is_malicious = check_in_RL_API(url)

        if is_malicious:
            return jsonify({"status": 2, "source": 3}), 200

        # if classification == "unknown" and check_in_VT_API(encoded_url):
        if check_in_VT_API(encoded_url):
            return jsonify({"status": 2, "source": 4}), 200

        return jsonify({"status": 0}), 200

    except Exception as e:
        return jsonify({"status": 0, "error": f"Internal server error: {str(e)}"}), 500
