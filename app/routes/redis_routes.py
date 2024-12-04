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
    
    # Start threads for searching in White Cache and Malware Cache concurrently
    white_thread = threading.Thread(target=search_in_white_cache, args=(md5_signature, result_dict, event))
    malware_thread = threading.Thread(target=search_in_malware_cache, args=(md5_signature, result_dict, event))
    
    white_thread.start()
    malware_thread.start()
    
    # Wait for one thread to finish
    event.wait()  # This will block until one thread sets the event
    
    # Join threads after the event has been set
    white_thread.join()
    malware_thread.join()
    
    # Determine the response based on the result
    if result_dict["status"] == 0:
        return jsonify({"status": "success", "message": "Found in White Cache"}), 200
    elif result_dict["status"] == 1:
        # Assuming the spyware category and name are stored in the Malware cache, you can fetch it here.
        redis_key = f"record:{md5_signature}"
        spyware_name = redis_service.redis_malware.hget(redis_key, "SpywareNameID")
        return jsonify({"status": "success", "message": f"Found in Malware Cache: {spyware_name}"}), 200
    else:
        return jsonify({"status": "success", "message": "Not found in either cache"}), 200


# def search_in_white_cache(md5_signature, result_dict, event):
#     """ Search for the MD5 in the White Cache. """
#     redis_key = f"record:{md5_signature}"
#     if redis_service.redis_white.exists(redis_key):
#         result_dict["found_in_white"] = True
#         result_dict["status"] = 0  # Found in White Cache
#         event.set()  # Trigger the termination of the other thread
#     time.sleep(2)  # Simulate time for processing

# def search_in_malware_cache(md5_signature, result_dict, event):
#     """ Search for the MD5 in the Malware Cache. """
#     redis_key = f"record:{md5_signature}"
#     if redis_service.redis_malware.exists(redis_key):
#         result_dict["found_in_malware"] = True
#         result_dict["status"] = 1  # Found in Malware Cache
#         event.set()  # Trigger the termination of the other thread
#     time.sleep(2)  # Simulate time for processing