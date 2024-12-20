from flask import Blueprint, jsonify, request
from app.services.malicious_urls_services import bulk_delete_malicious_urls, bulk_insert_malicious_urls

malicious_urls_bp = Blueprint('malicious_urls', __name__)

@malicious_urls_bp.route('/malicious_urls', methods=['POST'])
def Add_or_update_malicious_urls():
    try:
        data = request.get_json()
        if not isinstance(data, list):
            return jsonify({"error": "Invalid payload format, expected a list of records."}), 400

        result, success = bulk_insert_malicious_urls(data)
        if success:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@malicious_urls_bp.route('/delete-malicious-urls', methods=['DELETE'])
def delete_malicious_urls():
    try:
        data = request.get_json()
        if not data or 'md5_list' not in data:
            return jsonify({"error": "Invalid input. 'md5_list' field is required."}), 400

        md5_list = data['md5_list']
        result, success = bulk_delete_malicious_urls(md5_list)

        if success:
            return jsonify(result), 200
        else:
            return jsonify(result), 500
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
