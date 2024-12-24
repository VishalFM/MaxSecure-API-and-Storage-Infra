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

        # New custom cache connection
        pool_white_Domain_cache = redis.ConnectionPool(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            password=Config.REDIS_PASSWORD,
            db=Config.REDIS_DB_WHITE_DOMAIN_URL,
            decode_responses=True,
            max_connections=100
        )
        self.redis_white_Domain_cache = redis.StrictRedis(connection_pool=pool_white_Domain_cache)
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

    # for signature
    def save_to_redis(self, signature_map_white, signature_map_malware):
        try:
            with self.redis_white.pipeline() as white_pipeline, self.redis_malware.pipeline() as malware_pipeline:
                # Process white cache entries
                for signature, value in signature_map_white.items():
                    spyware_name, vendor_name, source_name = value.split("|")
                    if self.redis_malware.exists(signature):
                        self.redis_malware.delete(signature)
                    white_pipeline.set(signature, f"{spyware_name}|{vendor_name}|{source_name}")

                # Process malware cache entries
                for signature, value in signature_map_malware.items():
                    spyware_name, vendor_name, source_name = value.split("|")
                    if self.redis_white.exists(signature):
                        self.redis_white.delete(signature)
                    malware_pipeline.set(signature, f"{spyware_name}|{vendor_name}|{source_name}")

                white_pipeline.execute()
                malware_pipeline.execute()

            return True
        except Exception as e:
            return False

    def delete_from_redis(self, signature):
        redis_service.redis_white.delete(signature)
        redis_service.redis_malware.delete(signature)

    def delete_bulk_from_redis(self, signatures):
        for signature in signatures:
            self.delete_from_redis(signature)
            
    def bulk_insert_cache(self, cache_data, cache_type):
        try:
            print("In bulk_insert_cache ", cache_type)
            redis_cache = self.get_redis_cache(cache_type)
            pipeline = redis_cache.pipeline()
            for md5_hash, value in cache_data:
                if not redis_cache.exists(md5_hash):
                    pipeline.set(md5_hash, value)
            pipeline.execute()
        except redis.exceptions.RedisError:
            print(f"Error occured while inserting into {cache_type} Redis Cache")
            pass

    def get_redis_cache(self, cache_type):
        match cache_type:
            case "malicious_url":
                return self.redis_malicious_url
            case "main_domain_url":
                return self.redis_malicious_url
            case "white_main_domain_url":
                return self.redis_white_Domain_cache

    def _common_cache_search(self, hash_value, redis_client):
        try:
            return redis_client.get(str(hash_value)) or ""
        except redis.exceptions.RedisError:
            return ""

    def search_in_malicious_url_cache(self, md5_hash):
        return self._common_cache_search(md5_hash, self.redis_malicious_url)
        
    def search_in_domain_cache(self, domain_hash):
        return self._common_cache_search(domain_hash, self.redis_malicious_Main_Domain_url, is_domain=True)
    
    def search_in_White_main_domain_url_cache(self, md5_hash):
        return self._common_cache_search(md5_hash, self.redis_white_Domain_cache)
    
redis_service = RedisService()

def update_redis_cache_in_thread(record):
    redis_service.process_signature(record)

def search_in_white_cache(md5_signature, result_dict, event):
    redis_key = f"{md5_signature}"

    if redis_service.redis_white.exists(redis_key):
        result_dict["found_in_white"] = True
        result_dict["status"] =   []
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

def search_in_cache(md5_signature, result_dict, cache_type):
    redis_key = f"{md5_signature}"

    if cache_type == "white":
        redis_cache = redis_service.redis_white
        key_exists = redis_cache.exists(redis_key)
        if key_exists:
            cache_value = redis_cache.get(redis_key).split('|')  # Assuming it's stored in "SpywareName|VendorName|SourceName"
            return {
                "Spyware Name": cache_value[0],
                "Vendor Name": cache_value[1],
                "Source Name": cache_value[2],
                "status": 0  # status 0 indicates it was found in white cache
            }
        else:
            return {"status": 2}  # status 2 indicates not found in white cache

    elif cache_type == "malware":
        redis_cache = redis_service.redis_malware
        key_exists = redis_cache.exists(redis_key)
        if key_exists:
            cache_value = redis_cache.hget(redis_key, "SpywareNameAndCategory")  # Assuming it has a field "SpywareNameAndCategory"
            cache_value_parts = cache_value.split('|')
            return {
                "Spyware Name": cache_value_parts[0],
                "Category": cache_value_parts[1],
                "status": 1  # status 1 indicates it was found in malware cache
            }
        else:
            return {"status": 2}  # status 2 indicates not found in malware cache

    return None  # In case an invalid cache type is provided
