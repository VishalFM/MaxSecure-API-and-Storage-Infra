from flask import Blueprint, request, jsonify
from app.models.model import FileType
from app.services.redis_services import search_in_malware_cache, search_in_white_cache, RedisService
import threading
from app.utils.Cache import generate_md5_from_url

redis_bp = Blueprint('redis', __name__)
redis_service = RedisService()

@redis_bp.route('/search/<md5_signature>', methods=['GET'])
def search(md5_signature):
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
    API endpoint to search for a URL in the Malicious URL cache.
    Expects a query parameter 'url'.
    """
    try:
        # Get the 'url' query parameter from the request
        url = request.args.get('url')
        if not url:
            return jsonify({"status": "error", "message": "Missing 'url' query parameter"}), 400

        md5_hash = generate_md5_from_url(url)
        # Call the Redis service to search in the Malicious URL cache
        entry_status = redis_service.search_in_malicious_url_cache(md5_hash)

        # Handle different statuses based on the response from the cache search
        if entry_status["status"] == "found":
            return jsonify({
                "status": "success",
                "url": url,
                "entry_status": entry_status["entry_status"],
                "message": entry_status["message"]
            }), 200
        elif entry_status["status"] == "unknown":
            return jsonify({
                "status": "not_found",
                "url": url,
                "message": entry_status["message"]
            }), 404
        elif entry_status["status"] == "error":
            return jsonify({
                "status": "error",
                "message": entry_status["message"],
                "error": entry_status.get("error")
            }), 500
        else:
            return jsonify({"status": "error", "message": "Unexpected response from the cache"}), 500

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
