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

        # Lock for thread-safe operations
        self.lock = threading.Lock()

    def check_redis_connection(self):
        try:
            # Test connection to Redis (ping)
            response_white = self.redis_white.ping()
            response_malware = self.redis_malware.ping()

            if response_white and response_malware:
                print("Successfully connected to both White and Malware Redis caches.")
            else:
                print("Failed to connect to Redis.")
        except redis.exceptions.ConnectionError as e:
            print(f"Error connecting to Redis: {e}")

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
        """ Remove a signature from the cache. """
        with self.lock:
            try:
                if entry_status == 0:
                    self.redis_white.delete(f"record:{signature}")
                    print(f"Removed {signature} from White cache.")
                else:
                    self.redis_malware.delete(f"record:{signature}")
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
