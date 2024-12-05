from flask import Blueprint, request, jsonify
from app.models.model import FileType
from app.services.redis_services import search_in_malware_cache, search_in_white_cache, RedisService
import threading

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
    
@redis_bp.route('/checkRedisConnection', methods=['GET'])
def check_redis_connection_route(self):
    return redis_service.check_redis_connection()