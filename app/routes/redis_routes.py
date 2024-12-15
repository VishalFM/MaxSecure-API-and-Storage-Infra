import base64
from wsgiref.validate import validator
from flask import Blueprint, request, jsonify
from app.models.model import FileType
from app.services.redis_services import search_in_malware_cache, search_in_white_cache, RedisService
import threading
from app.utils.parse_url import extract_main_domain, get_md5_from_url

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
  
@redis_bp.route('/searchMaliciousUrl', methods=['GET'])
def search_malicious_url():
    """
    API endpoint to search for a URL in the Malicious URL cache and Domain cache.
    Expects a query parameter 'url' in base64 encoded format.
    """
    try:
        url = request.args.get('url')
        # is_base64 = request.args.get('is_base64', 'false').lower() == 'true'

        if not url:
            return jsonify({"status": "error", "status_code": 400}), 400

        try:
            decoded_url = base64.b64decode(url).decode('utf-8')
            if validator.url(decoded_url):  
                url = decoded_url
        except Exception:
            pass  # If decoding fails, assume the URL is already in plain text

        md5_hash = get_md5_from_url(url)
        domain = extract_main_domain(url)
        domain_hash = get_md5_from_url(domain)

        # Shared results dictionary
        results = {"malicious": None, "domain": None}

        # Threaded search
        def search_malicious():
            results["malicious"] = redis_service.search_in_malicious_url_cache(md5_hash)

        def search_domain():
            results["domain"] = redis_service.search_in_domain_cache(domain_hash)

        # Create and start threads
        malicious_thread = threading.Thread(target=search_malicious)
        domain_thread = threading.Thread(target=search_domain)
        malicious_thread.start()
        domain_thread.start()

        # Wait for both threads to finish
        malicious_thread.join()
        domain_thread.join()

        malicious_result = results["malicious"]
        domain_result = results["domain"]

        if malicious_result and malicious_result["entry_status"] == 1:
            status_code = 2
        elif domain_result:
            status_code = (
                1 if domain_result["entry_status"] == 1 and malicious_result["entry_status"] == 0
                else 0
            )
        else:
            status_code = 0

        return jsonify({"status": "success", "status_code": status_code}), 200

    except Exception as e:
        return jsonify({"status": "error", "status_code": 500}), 500

@redis_bp.route('/checkRedisConnection', methods=['GET'])
def check_redis_connection_route():
    return redis_service.check_redis_connection()