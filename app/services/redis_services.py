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
        redis_key = f"record:{record['Signature']}"
        
        redis_data = {
            "Signature": record['Signature'],
            "EntryStatus": record['EntryStatus'],
            "SpywareNameID": record['SpywareNameID'],
            "SourceID": record['SourceID'],
            "FileTypeID": record['FileTypeID'],
            "SpywareNameAndCategory": record['SpywareNameAndCategory'],
            "HitsCount": record.get('HitsCount', 0)
        }
        
        # Lock to ensure thread-safety
        with self.lock:
            if record['EntryStatus'] == 0:
                print("Adding to White cache...")
                if self.redis_white.exists(redis_key):
                    print(f"{record['Signature']} already exists in White cache. Skipping addition.")
                    return
                try:
                    # Insert fields one by one into the hash
                    for field, value in redis_data.items():
                        self.redis_white.hset(redis_key, field, value)
                    
                    # Set the index for quick lookup
                    self.redis_white.set(f"index:{record['Signature']}", redis_key)
                    print(f"Successfully added {record['Signature']} to White cache.")
                except redis.exceptions.RedisError as e:
                    print(f"Error adding {record['Signature']} to White cache: {e}")
            else:
                print("Adding to Malware cache...")
                if self.redis_malware.exists(redis_key):
                    print(f"{record['Signature']} already exists in Malware cache. Skipping addition.")
                    return
                try:
                    # Insert fields one by one into the hash
                    for field, value in redis_data.items():
                        self.redis_malware.hset(redis_key, field, value)
                    
                    # Set the index for quick lookup
                    self.redis_malware.set(f"index:{record['Signature']}", redis_key)
                    print(f"Successfully added {record['Signature']} to Malware cache.")
                except redis.exceptions.RedisError as e:
                    print(f"Error adding {record['Signature']} to Malware cache: {e}")

    def remove_from_cache(self, signature, entry_status):
        """ Remove a signature and its index from the cache. """
        with self.lock:
            try:
                if entry_status == 0:
                    # Remove the record and the index from the White cache
                    self.redis_white.delete(f"record:{signature}")
                    self.redis_white.delete(f"index:{signature}")
                    print(f"Removed {signature} from White cache.")
                else:
                    # Remove the record and the index from the Malware cache
                    self.redis_malware.delete(f"record:{signature}")
                    self.redis_malware.delete(f"index:{signature}")
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
    
    def add_to_malicious_url_cache(self, md5_signature, md5_hash_main_domain, entry_status):
        """ Store MD5 signature and entry status in the Malicious URL cache and the Malicious Main Domain URL cache. """
        # Create keys for the malicious URL cache and the malicious main domain URL cache
        malicious_url_key = f"malicious_url:{md5_signature}"
        malicious_domain_key = f"malicious_domain_url:{md5_hash_main_domain}"

        malicious_url_data = {
            "Signature": md5_signature,
            "EntryStatus": entry_status
        }

        malicious_main_domain_url_data = {
            "Signature": md5_hash_main_domain,
            "EntryStatus": entry_status
        }

        # Lock to ensure thread-safety
        with self.lock:
            try:
                # Check if the signature already exists in either cache to prevent overwriting
                if self.redis_malicious_url.exists(malicious_url_key):
                    print(f"{md5_signature} already exists in Malicious URL cache.")
                else:
                    # Insert fields into the malicious URL cache
                    for field, value in malicious_url_data.items():
                        self.redis_malicious_url.hset(malicious_url_key, field, value)

                    # Set the index for quick lookup
                    # self.redis_malicious_url.set(f"index:{md5_signature}", malicious_url_key)
                    print(f"Successfully added {md5_signature} to Malicious URL cache.")

                if self.redis_malicious_Main_Domain_url.exists(malicious_domain_key):
                    print(f"{md5_hash_main_domain} already exists in Malicious Domain URL cache.")
                else:
                    # Insert fields into the malicious main domain URL cache
                    for field, value in malicious_main_domain_url_data.items():
                        self.redis_malicious_Main_Domain_url.hset(malicious_domain_key, field, value)

                    # Set the index for quick lookup
                    # self.redis_malicious_Main_Domain_url.set(f"index:{md5_hash_main_domain}", malicious_domain_key)
                    print(f"Successfully added {md5_hash_main_domain} to Malicious Main Domain URL cache.")
                    
            except redis.exceptions.RedisError as e:
                print(f"Error adding to malicious URL cache: {e}")
                if 'md5_signature' in locals():
                    print(f"Problem occurred with MD5 signature: {md5_signature}")
                if 'md5_hash_main_domain' in locals():
                    print(f"Problem occurred with MD5 main domain: {md5_hash_main_domain}")

    def search_in_malicious_url_cache(self, md5_hash):
        """
        Search for the MD5 of a URL in the Malicious URL cache.

        Args:
            md5_hash (str): The MD5 hash of the URL.

        Returns:
            dict: A dictionary containing the status and additional details:
                - "status" (str): "found" or "unknown".
                - "entry_status" (str, optional): The value associated with the MD5 hash in the cache.
                - "message" (str): A descriptive message.
                - "error" (str, optional): Error details if an exception occurs.
        """
        try:
            # Check if the MD5 hash exists in the malicious URL cache
            redis_key = f"malicious_url:{md5_hash}"
            entry_status = self.redis_malicious_url.hget(redis_key, "EntryStatus")

            if entry_status:
                return {
                    "status": "found",
                    "entry_status": entry_status.decode('utf-8') if isinstance(entry_status, bytes) else entry_status,
                    "message": f"The MD5 hash {md5_hash} exists in the Malicious URL cache.",
                }
            else:
                return {
                    "status": "unknown",
                    "message": f"The MD5 hash {md5_hash} was not found in the Malicious URL cache.",
                }
        except redis.exceptions.RedisError as e:
            print(f"Error searching in Malicious URL cache: {e}")
            return {
                "status": "error",
                "message": "An error occurred while searching in the Malicious URL cache.",
                "error": str(e),
            }


redis_service = RedisService()
def update_redis_cache_in_thread(record):
    """ Helper function to run Redis operations in a separate thread. """
    redis_service.process_signature(record)

def search_in_white_cache(md5_signature, result_dict, event):
    """Search for the MD5 in the White Cache."""
    redis_key = f"record:{md5_signature}"

    print("redis_key :: ", redis_key)
    if redis_service.redis_white.exists(redis_key):
        print("found in white")
        result_dict["found_in_white"] = True
        result_dict["status"] = 0  # Found in White Cache
        event.set()  # Trigger the termination of the other thread
    else:
        print("not found in white")
        result_dict["found_in_white"] = False

    print("if condition passed in white")
    time.sleep(2)  # Simulate time for processing

def search_in_malware_cache(md5_signature, result_dict, event):
    """Search for the MD5 in the Malware Cache."""
    redis_key = f"record:{md5_signature}"
    print("redis_key :: ", redis_key)
    if redis_service.redis_malware.exists(redis_key):
        print("found in malware")
        result_dict["found_in_malware"] = True
        result_dict["status"] = 1  # Found in Malware Cache
        event.set()  # Trigger the termination of the other thread
    else:
        print("not found in malware")
        result_dict["found_in_malware"] = False

    print("if condition passed in malware")
    time.sleep(2)  # Simulate time for processing

def insert_into_malicious_url( md5_signature, entry_status):
    return redis_service.add_to_malicious_url_cache(md5_signature, entry_status)
    