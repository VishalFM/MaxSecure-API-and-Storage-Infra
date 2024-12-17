from flask import Blueprint, jsonify
import psycopg2

from config import Config

test = Blueprint('test', __name__)
pg_connection = Blueprint('postgres', __name__)

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