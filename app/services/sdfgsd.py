import csv
import os
import sys
import json
import hashlib
from urllib.parse import urlparse
import psycopg2
from psycopg2 import sql
import redis
import json
import traceback

REDIS_DB_WHITE = 0
REDIS_DB_MALWARE = 1
REDIS_DB_MALICIOUS_URL = 2
REDIS_DB_MALICIOUS_MAIN_DOMAIN_URL = 3

redis_client_murls = redis.StrictRedis(host='localhost', port=6379, password='Maxsecureredis#$2024',
                                       db=REDIS_DB_MALICIOUS_URL, decode_responses=True)
redis_client_mruls_domain = redis.StrictRedis(host='localhost', port=6379, password='Maxsecureredis#$2024',
                                              db=REDIS_DB_MALICIOUS_MAIN_DOMAIN_URL, decode_responses=True)

# redis_client_murls = redis.StrictRedis(host='localhost', port=6379, password='',
#                                        db=REDIS_DB_MALICIOUS_URL, decode_responses=True)
# redis_client_mruls_domain = redis.StrictRedis(host='localhost', port=6379, password='',
#                                               db=REDIS_DB_MALICIOUS_MAIN_DOMAIN_URL, decode_responses=True)

# Connect to PostgreSQL
db_config = {
    "host": 'antivirus-postgres-test.cluster-cpsi00o0qxrg.us-east-1.rds.amazonaws.com',
    "dbname": 'antivirusdb',
    "user": 'antiviruspgsql',
    "password": 'Maxsecurepgsql#$2024',
    "port": 5432
}

# db_config = {
#     "host": 'localhost',
#     "dbname": 'MaxSecureDB1',
#     "user": 'postgres',
#     "password": 'system',
#     "port": 5432
# }

# Insert query
insert_query = """
INSERT INTO "MaliciousURLs" (
    "URL", 
    "VendorID", 
    "EntryStatus", 
    "Score", 
    "MD5", 
    "MainDomain", 
    "Main_domain_MD5"
) 
VALUES (%s, %s, %s, %s, %s, %s, %s)
"""


def process_folder_structure(base_folder):
    try:
        processing_started = False
        i = 1
        for root, _, files in os.walk(base_folder):
            for file in files:
                file_path = os.path.join(root, file)
                print(f"{i}. Processing file: {file_path}")
                i += 1

                # Start processing only after encountering the target file
                # if not processing_started:
                #     if file_path == "/home/ubuntu/Files/MRGURLs-CSV/202411072132_ThreatUrls.csv":
                #         processing_started = True
                #     else:
                #         continue  # Skip all files before the target file

                # for MRG Vender & Av-test Free Url folder
                # with open(file_path, 'r') as f:
                #     urls_data = [line.strip().split(',') for line in f if line.strip()]  # Assuming CSV format

                # for AVtest Vender Folder
                with open(file_path, 'r', encoding='utf-8') as f:
                    csv_reader = csv.reader(f)
                    next(csv_reader, None)  # Skip the header row
                    urls_data = [row for row in csv_reader]   # Read all rows, ensuring quoted fields are handled
                    
                result = bulk_insert_malicious_urls(urls_data)
                if result == 'success':
                    print(f"File {file_path} processed successfully")
                else:
                    print(f"Error processing file {file_path}")
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)


def bulk_insert_malicious_urls(urls_data):
    try:
        murls_redis = {}
        mruls_domain_redis = {}
        databaseEntries = []
        for url in urls_data:
            normalized_url = url[0].strip().lower()
            # score = 0.0 # for MRG 
            score = url[3] # for AVtest

            # normalized_url = normalized_url.replace("'", "").replace("\"", "").split(" ")[0]
            parsed_url = urlparse(normalized_url) # for Av-test
            domain = parsed_url.netloc  # Extract the netloc (domain) part of the URL

            md5_hash = hashlib.md5(normalized_url.encode('utf-8')).hexdigest()
            md5_hash_main_domain = hashlib.md5(domain.encode('utf-8')).hexdigest()

            # for Avtest
            vendor = 1 
            vendor_name = "AVTest"  

            # for MRG 
            # vendor = 1    
            # vendor_name = "AVTest"  

            entry_status = 1

            murls_redis[md5_hash] = f"{entry_status}|{score}|{vendor_name}"
            mruls_domain_redis[md5_hash_main_domain] = f"{entry_status}|{score}|{vendor_name}"

            databaseEntries.append((normalized_url, vendor, entry_status, score, md5_hash, domain, md5_hash_main_domain))

        if databaseEntries:
            if databaseInsert(databaseEntries):
                redisInsert(murls_redis, mruls_domain_redis)

        return 'success'
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)


def redisInsert(murls_redis, mruls_domain_redis):
    # Set the data in Redis
    redis_client_murls.mset(murls_redis)
    redis_client_mruls_domain.mset(mruls_domain_redis)



def databaseInsert(data, batch_size=1000):
    conn = None
    try:
        conn_str = (
            f"dbname='{db_config['dbname']}' user='{db_config['user']}' "
            f"password='{db_config['password']}' host='{db_config['host']}' port='{db_config['port']}'"
        )
        # Connect to the database
        with psycopg2.connect(conn_str) as conn:
            with conn.cursor() as cursor:
                # Split data into batches and execute each batch
                for i in range(0, len(data), batch_size):
                    batch = data[i:i + batch_size]
                    try:
                        cursor.execute('BEGIN;')  # Start a transaction
                        for record in batch:
                            try:
                                cursor.execute(insert_query, record)
                            except psycopg2.errors.UniqueViolation as e:
                                conn.rollback()  # Rollback the transaction
                                print(f"UniqueViolation encountered: {e}. Skipping this record.")
                            except Exception as e:
                                conn.rollback()  # Rollback the transaction
                                print(f"Error inserting data: {e}")
                                traceback.print_exc()
                                sys.exit(1)
                        conn.commit()  # Commit the transaction
                        print(f"Inserted batch of {len(batch)} records.")
                    except Exception as e:
                        conn.rollback()  # Rollback the transaction for the whole batch
                        print(f"Error processing batch: {e}")
                        traceback.print_exc()
                        # Optionally, continue to the next batch or handle as needed
                print(f"Total {len(data)} records inserted successfully.")
        return True
    except psycopg2.Error as e:
        traceback.print_exc()
        sys.exit(1)
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    # base_folder_path = "/home/ubuntu/Files/17-12-24MURL/20-12-24"
    base_folder_path = "/home/ubuntu/Files/AvtestURL"
    # base_folder_path = "/home/ubuntu/Files/Av-Test Free URl"
    # base_folder_path = "/Users/VISHAL/OneDrive/Desktop/Flairminds/Fable malware detection - Master/Test Data"
    process_folder_structure(base_folder_path)
