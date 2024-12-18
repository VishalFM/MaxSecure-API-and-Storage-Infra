from flask import Blueprint, jsonify
import psycopg2

from app.services.redis_services import search_in_malware_cache, search_in_white_cache, RedisService
from config import Config

test = Blueprint('test', __name__)
pg_connection = Blueprint('postgres', __name__)
redis_bp = Blueprint('redis', __name__)

redis_service = RedisService()

@test.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "success", "message": "Host is reachable!"}), 200

@pg_connection.route('/test-db-connection', methods=['GET'])
def test_db_connection():
    try:
        connection = psycopg2.connect(
            host=Config.POSTGRES_HOST,
            port=Config.POSTGRES_PORT,
            database=Config.POSTGRES_DB,
            user=Config.POSTGRES_USER,
            password=Config.POSTGRES_PASSWORD
        )
        cursor = connection.cursor()
        cursor.execute("SELECT 1;")
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        return jsonify({"status": "success", "message": "DB connection is working!", "query_result": result}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@redis_bp.route('/checkRedisConnection', methods=['GET'])
def check_redis_connection_route():
    return redis_service.check_redis_connection()
