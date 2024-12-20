import base64
from flask import Blueprint, request, jsonify
from app.services.RL_VT_API_services import check_in_RL_API, check_in_VT_API
from app.services.redis_services import search_in_malware_cache, search_in_white_cache, RedisService
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
    event = threading.Event()

    white_thread = threading.Thread(target=search_in_white_cache, args=(md5_signature, result_dict, event))
    malware_thread = threading.Thread(target=search_in_malware_cache, args=(md5_signature, result_dict, event))

    white_thread.start()
    malware_thread.start()

    event.wait(timeout=1)

    white_thread.join()
    malware_thread.join()

    if not result_dict.get("found_in_white", False) and not result_dict.get("found_in_malware", False):
        return jsonify({"status": "success", "message": "Not found in either cache"}), 200
    else:
        if result_dict["status"] == 0:
            return jsonify({"status": "success", "message": "Found in White Cache"}), 200
        elif result_dict["status"] == 1:
            redis_key = f"record:{md5_signature}"
            SpywareNameAndCategory = redis_service.redis_malware.hget(redis_key, "SpywareNameAndCategory")
            return jsonify({"status": "success", "message": f"Found in Malware Cache: {SpywareNameAndCategory}"}), 200
    return jsonify({"status": "success", "message": "Not found in either cache"}), 200


@search_bp.route('/searchMaliciousUrl', methods=['GET'])
def search_malicious_url():
    try:
        url = request.args.get('url')
        if not url:
            return jsonify({"status": 0}), 200
        try:
            url = base64.b64decode(url).decode('utf-8')
        except Exception:
            return jsonify({"status": 0, "error": "Invalid base64 encoding"}), 500
        md5_hash = get_md5_from_url(url)

        results_malicious = redis_service.search_in_malicious_url_cache(md5_hash)
        if results_malicious:
            return jsonify({"status": 2, "source": 1, "Vendor": results_malicious.split('|')[2], "Score": results_malicious.split('|')[1]}), 200

        classification = check_in_RL_API(url)
        if classification in ["malicious", "suspicious"]:
            return jsonify({"status": 2, "source": 3}), 200
        elif classification in ["unknown"] and check_in_VT_API(url):
            return jsonify({"status": 2, "source": 4}), 200

        return jsonify({"status": 0}), 200

    except Exception as e:
        return jsonify({"status": 0, "error": "Internal server error"}), 500
