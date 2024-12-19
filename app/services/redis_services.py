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

    def add_to_cache(self, record):
        redis_key = f"{record['Signature']}"
        redis_data = {
            "EntryStatus": record['EntryStatus'],
            "SpywareNameAndCategory": record['SpywareNameAndCategory'],
            "HitsCount": record.get('HitsCount', 0)
        }

        redis_client = self.redis_white if record['EntryStatus'] == 0 else self.redis_malware

        with self.lock:
            try:
                if not redis_client.exists(redis_key):
                    redis_client.hmset(redis_key, redis_data)
            except redis.exceptions.RedisError as e:
                print(f"Error adding to cache: {e}")

    def remove_from_cache(self, signature, entry_status):
        with self.lock:
            try:
                if entry_status == 0:
                    self.redis_white.delete(f"{signature}")
                else:
                    self.redis_malware.delete(f"{signature}")
            except redis.exceptions.RedisError:
                pass

    def process_signature(self, record):
        if record['EntryStatus'] == 0:
            self.remove_from_cache(record['Signature'], 1)
            self.add_to_cache(record)
        else:
            self.remove_from_cache(record['Signature'], 0)
            self.add_to_cache(record)
    
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
