import threading
# from datetime import 
import time
import redis
from config import Config
import threading

class RedisService:
    def __init__(self):
        self.redis_white = redis.StrictRedis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            password=Config.REDIS_PASSWORD,
            db=Config.REDIS_DB_WHITE,
            decode_responses=True
        )

        self.redis_malware = redis.StrictRedis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            password=Config.REDIS_PASSWORD,
            db=Config.REDIS_DB_MALWARE,
            decode_responses=True
        )

        self.redis_malicious_url = redis.StrictRedis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            password=Config.REDIS_PASSWORD,
            db=Config.REDIS_DB_MALICIOUS_URL,
            decode_responses=True
        )

        self.redis_malicious_Main_Domain_url = redis.StrictRedis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            password=Config.REDIS_PASSWORD,
            db=Config.REDIS_DB_MALICIOUS_MAIN_DOMAIN_URL,
            decode_responses=True
        )

        # Lock for thread-safe operations
        self.lock = threading.Lock()

    def check_redis_connection(self):
        try:
            # Test connection to Redis (ping)
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
        """ Add a record to the appropriate cache based on entry status. """
        redis_key = f"{record['Signature']}"
        
        redis_data = {
            "EntryStatus": record['EntryStatus'],
            "SpywareNameAndCategory": record['SpywareNameAndCategory'],
            "HitsCount": record.get('HitsCount', 0)
        }
        
        # Lock to ensure thread-safety
        with self.lock:
            if record['EntryStatus'] == 0:
                print("Adding to White cache...")
                if self.redis_white.exists(redis_key):
                    # print(f"{record['Signature']} already exists in White cache. Skipping addition.")
                    return
                try:
                    for field, value in redis_data.items():
                        self.redis_white.hset(redis_key, field, value)
                    
                except redis.exceptions.RedisError as e:
                    print(f"Error adding {record['Signature']} to White cache: {e}")
            else:
                if self.redis_malware.exists(redis_key):
                    return
                try:
                    for field, value in redis_data.items():
                        self.redis_malware.hset(redis_key, field, value)

                except redis.exceptions.RedisError as e:
                    print(f"Error adding {record['Signature']} to Malware cache: {e}")

    def remove_from_cache(self, signature, entry_status):
        """ Remove a signature and its index from the cache. """
        with self.lock:
            try:
                if entry_status == 0:
                    self.redis_white.delete(f"{signature}")
                    print(f"Removed {signature} from White cache.")
                else:
                    self.redis_malware.delete(f"{signature}")
                    print(f"Removed {signature} from Malware cache.")
            except redis.exceptions.RedisError as e:
                print(f"Error removing {signature} from cache: {e}")

    def process_signature(self, record):
        """ Handles cache updates in a thread. """
        print(f"Processing record {record['Signature']}...")
        if record['EntryStatus'] == 0:
            # Remove from Malware cache and add to White cache
            self.remove_from_cache(record['Signature'], 1)
            self.add_to_cache(record)
        else:
            # Remove from White cache and add to Malware cache
            self.remove_from_cache(record['Signature'], 0)
            self.add_to_cache(record)
    
    def bulk_insert_malicious_url_cache(self, url_cache_data):
        try:
            url_cache_dict = {
                f"{md5_hash}": entry_status
                for md5_hash, entry_status in url_cache_data
                if not self.redis_malicious_url.exists(f"{md5_hash}")
            }

            # Perform mset to insert all new keys at once
            if url_cache_dict:
                self.redis_malicious_url.mset(url_cache_dict)

            print("Bulk malicious URLs added to cache.")

        except redis.exceptions.RedisError as e:
            print(f"Error adding bulk malicious URLs to cache: {e}")

    def bulk_insert_main_domain_url_cache(self, domain_cache_data):
        try:
            domain_cache_dict = {
                f"{md5_hash_main_domain}": entry_status
                for md5_hash_main_domain, entry_status in domain_cache_data
                if not self.redis_malicious_Main_Domain_url.exists(f"{md5_hash_main_domain}")
            }
            if domain_cache_dict:
                self.redis_malicious_Main_Domain_url.mset(domain_cache_dict)
            
            print("Bulk main domain URLs added to cache.")
        
        except redis.exceptions.RedisError as e:
            print(f"Error adding bulk main domain URLs to cache: {e}")

    def _common_cache_search(self, hash_value, redis_client, is_domain=False):
        try:
            print("hash_value", hash_value)
            redis_key = str(hash_value)
            if is_domain:
                # search in domain cache
                print("redis_client.get(redis_key) > ", redis_client.get(redis_key))
                if redis_client.get(redis_key):
                    return True
            else:
                #search in malicious cache
                print("redis_client.get(redis_key) > ", redis_client.get(redis_key))
                if redis_client.get(redis_key):
                    return True
            return False
            
        except redis.exceptions.RedisError as e:
            return False

    def search_in_malicious_url_cache(self, md5_hash):
        return self._common_cache_search(
            md5_hash, 
            self.redis_malicious_url, 
        )
        
    def search_in_domain_cache(self, domain_hash):
        return self._common_cache_search(
            domain_hash, 
            self.redis_malicious_Main_Domain_url, 
            is_domain=True
        )
    
redis_service = RedisService()
def update_redis_cache_in_thread(record):
    """ Helper function to run Redis operations in a separate thread. """
    redis_service.process_signature(record)

def search_in_white_cache(md5_signature, result_dict, event):
    """Search for the MD5 in the White Cache."""
    redis_key = f"{md5_signature}"

    if redis_service.redis_white.exists(redis_key):
        result_dict["found_in_white"] = True
        result_dict["status"] = 0  # Found in White Cache
        event.set()  # Trigger the termination of the other thread
    else:
        result_dict["found_in_white"] = False

    time.sleep(2)  # Simulate time for processing

def search_in_malware_cache(md5_signature, result_dict, event):
    """Search for the MD5 in the Malware Cache."""
    redis_key = f"{md5_signature}"

    if redis_service.redis_malware.exists(redis_key):
        result_dict["found_in_malware"] = True
        result_dict["status"] = 1  # Found in Malware Cache
        event.set()  # Trigger the termination of the other thread
    else:
        result_dict["found_in_malware"] = False

    time.sleep(2)  # Simulate time for processing
    