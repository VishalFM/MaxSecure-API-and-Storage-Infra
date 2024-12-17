import base64
from wsgiref.validate import validator
from flask import Blueprint, request, jsonify
from app.models.model import FileType
from app.services.RL_VT_API_services import check_in_RL_API, check_in_VT_API
from app.services.redis_services import search_in_malware_cache, search_in_white_cache, RedisService
import threading
from app.utils.parse_url import extract_main_domain, get_main_domain, get_md5_from_url

redis_bp = Blueprint('redis', __name__)
redis_service = RedisService()

@redis_bp.route('/search/<md5_signature>', methods=['GET'])
def search(md5_signature):
    try:
        md5_signature = base64.b64decode(md5_signature).decode('utf-8')
    except Exception as e:
        return jsonify({"status": "error", "message": "Invalid Base64 encoding", "error": str(e)}), 400

    """Search for a record in both caches."""
    result_dict = {"found_in_white": False, "found_in_malware": False, "status": 2}  # Default Status 2 (Not Found)
    
    # Event to notify when a thread has found the result
    event = threading.Event()
    
    print("thread creation below")
    # Start threads for searching in White Cache and Malware Cache concurrently
    white_thread = threading.Thread(target=search_in_white_cache, args=(md5_signature, result_dict, event))
    malware_thread = threading.Thread(target=search_in_malware_cache, args=(md5_signature, result_dict, event))
    print("thread created")
    
    white_thread.start()
    malware_thread.start()
    
    print("both thread started")

    # Wait for one thread to finish
    event.wait(timeout=1) # This will block until one thread sets the event
    print("Event wait")
    
    # Join threads after the event has been set
    white_thread.join()
    malware_thread.join()
    print("thread joined")
    
    print("result_dict[\"status\"] --- ", result_dict["status"])

    # Final result check
    if not result_dict.get("found_in_white", False) and not result_dict.get("found_in_malware", False):
        return jsonify({"status": "success", "message": "Not found in either cache"}), 200
    else:
        print(f"Search result: {result_dict}")
        # Determine the response based on the result
        if result_dict["status"] == 0:
            return jsonify({"status": "success", "message": "Found in White Cache"}), 200
        elif result_dict["status"] == 1:
            # Assuming the spyware category and name are stored in the Malware cache, you can fetch it here.
            redis_key = f"record:{md5_signature}"
            SpywareNameAndCategory = redis_service.redis_malware.hget(redis_key, "SpywareNameAndCategory")
            return jsonify({"status": "success", "message": f"Found in Malware Cache: {SpywareNameAndCategory}"}), 200
    return jsonify({"status": "success", "message": "Not found in either cache"}), 200
  
from flask import jsonify

@redis_bp.route('/searchMaliciousUrl', methods=['GET'])
def search_malicious_url():
    try:
        url = request.args.get('url')
        if not url:
            return jsonify({"status": 0}), 200  # Return JSON with the status
        print("url > ", url)
        try:
            url = base64.b64decode(url).decode('utf-8')
        except Exception:
            return jsonify({"status": 0, "error": "Invalid base64 encoding"}), 500  # Include error details in JSON
        print("url > ", url)
        md5_hash = get_md5_from_url(url)
        print("md5_hash > ", md5_hash)
        print("extract_main_domain(url) > ",extract_main_domain(url))
        domain_hash = get_md5_from_url(get_main_domain(url))

        print("md5_hash >",md5_hash)
        results_malicious = redis_service.search_in_malicious_url_cache(md5_hash)
        print("results_malicious > ", results_malicious)
        if results_malicious == 1:
            return jsonify({"status": 2, "message": "Malicious URL found"}), 200

        results_domain = redis_service.search_in_domain_cache(domain_hash)
        print("results_domain > ", results_domain)
        
        if results_domain == 1:
            return jsonify({"status": 1, "message": "Malicious domain found"}), 200

        # Check external APIs if nothing is found in cache
        if check_in_RL_API(url) or check_in_VT_API(url):
            return jsonify({"status": 2, "message": "Malicious URL found in external API"}), 200

        return jsonify({"status": 0, "message": "No malicious content found"}), 200

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({"status": 0, "error": "Internal server error"}), 500  # Include generic error details

@redis_bp.route('/checkRedisConnection', methods=['GET'])
def check_redis_connection_route():
    return redis_service.check_redis_connection()