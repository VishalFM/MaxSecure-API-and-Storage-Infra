import threading
import time
import redis
from config import Config

class RedisService:
    def __init__(self):
        pool_white = redis.ConnectionPool(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            password=Config.REDIS_PASSWORD,
            db=Config.REDIS_DB_WHITE,
            decode_responses=True,
            max_connections = 100
        )
        self.redis_white = redis.StrictRedis(connection_pool=pool_white)

        pool_malware = redis.ConnectionPool(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            password=Config.REDIS_PASSWORD,
            db=Config.REDIS_DB_MALWARE,
            decode_responses=True,
            max_connections=100
        )
        self.redis_malware = redis.StrictRedis(connection_pool=pool_malware)

        pool_malicious_url = redis.ConnectionPool(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            password=Config.REDIS_PASSWORD,
            db=Config.REDIS_DB_MALICIOUS_URL,
            decode_responses=True,
            max_connections=100
        )
        self.redis_malicious_url = redis.StrictRedis(connection_pool=pool_malicious_url)

        pool_main_domain = redis.ConnectionPool(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            password=Config.REDIS_PASSWORD,
            db=Config.REDIS_DB_MALICIOUS_MAIN_DOMAIN_URL,
            decode_responses=True,
            max_connections=100
        )
        self.redis_malicious_Main_Domain_url = redis.StrictRedis(connection_pool=pool_main_domain)

        self.lock = threading.Lock()

    def check_redis_connection(self):
        try:
            response_white = self.redis_white.ping()
            response_malware = self.redis_malware.ping()

            if response_white and response_malware:
                status_message = "Successfully connected to both White and Malware Redis caches."
                status_code = 200
            else:
                status_message = "Failed to connect to Redis."
                status_code = 500

            return {"status": status_message}, status_code

        except redis.exceptions.ConnectionError as e:
            return {"status": f"Error connecting to Redis: {e}"}, 500


    def save_to_redis(self, signature_map):
        try:
            with self.redis_white.pipeline() as white_pipeline, self.redis_malware.pipeline() as malware_pipeline:
                for key, value in signature_map.items():
                    signature, entry_status = key.split("|")
                    spyware_name, vendor_name = value.split("|")

                    if entry_status == "0":
                        if self.redis_malware.exists(signature):
                            self.redis_malware.delete(signature)
                            print(f"Moved from Malware to White cache: {signature}")

                        white_pipeline.set(signature, f"{spyware_name}|{vendor_name}")
                        print(f"Queued for White cache: {signature} -> {spyware_name}|{vendor_name}")

                    elif entry_status == "1":
                        if self.redis_white.exists(signature):
                            self.redis_white.delete(signature)
                            print(f"Moved from White to Malware cache: {signature}")

                        malware_pipeline.set(signature, f"{spyware_name}|{vendor_name}")
                        print(f"Queued for Malware cache: {signature} -> {spyware_name}|{vendor_name}")

                white_pipeline.execute()
                malware_pipeline.execute()

            print("Data saved to Redis successfully.")
            return True

        except Exception as e:
            print(f"Error saving to Redis: {str(e)}")
            return False

    def delete_from_redis(signature):
        redis_service.redis_white.delete(signature)
        redis_service.redis_malware.delete(signature)


    def bulk_insert_malicious_url_cache(self, url_cache_data):
        try:
            url_cache_dict = {
                f"{md5_hash}": entry_status
                for md5_hash, entry_status in url_cache_data
                if not self.redis_malicious_url.exists(f"{md5_hash}")
            }

            if url_cache_dict:
                self.redis_malicious_url.mset(url_cache_dict)

        except redis.exceptions.RedisError:
            pass

    def bulk_insert_main_domain_url_cache(self, domain_cache_data):
        try:
            domain_cache_dict = {
                f"{md5_hash_main_domain}": entry_status
                for md5_hash_main_domain, entry_status in domain_cache_data
                if not self.redis_malicious_Main_Domain_url.exists(f"{md5_hash_main_domain}")
            }
            if domain_cache_dict:
                self.redis_malicious_Main_Domain_url.mset(domain_cache_dict)
        
        except redis.exceptions.RedisError:
            pass

    def _common_cache_search(self, hash_value, redis_client, is_domain=False):
        try:
            redis_key = str(hash_value)
            if is_domain:
                if redis_client.get(redis_key):
                    return True
            else:
                if redis_client.get(redis_key):
                    return True
            return False
        
        except redis.exceptions.RedisError:
            return False

    def search_in_malicious_url_cache(self, md5_hash):
        return self._common_cache_search(md5_hash, self.redis_malicious_url)
        
    def search_in_domain_cache(self, domain_hash):
        return self._common_cache_search(domain_hash, self.redis_malicious_Main_Domain_url, is_domain=True)
    
redis_service = RedisService()

def update_redis_cache_in_thread(record):
    redis_service.process_signature(record)

def search_in_white_cache(md5_signature, result_dict, event):
    redis_key = f"{md5_signature}"

    if redis_service.redis_white.exists(redis_key):
        result_dict["found_in_white"] = True
        result_dict["status"] = 0
        event.set()
    else:
        result_dict["found_in_white"] = False

    time.sleep(2)

def search_in_malware_cache(md5_signature, result_dict, event):
    redis_key = f"{md5_signature}"

    if redis_service.redis_malware.exists(redis_key):
        result_dict["found_in_malware"] = True
        result_dict["status"] = 1
        event.set()
    else:
        result_dict["found_in_malware"] = False

    time.sleep(2)
