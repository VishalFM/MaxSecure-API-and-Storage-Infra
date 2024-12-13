import hashlib
from urllib.parse import urlparse
from app.models.model import MaliciousURLs, Source
from app.extensions import db
from app.services.source_services import get_source_ids, validate_and_insert_sources
from app.services.redis_services import RedisService

redis_service = RedisService()

def bulk_insert_malicious_urls(urls_data, batch_size=10000):
    try:
        # Preload all existing vendors and malicious URLs into memory
        vendors = {vendor.Name.lower(): vendor.ID for vendor in Source.query.all()}
        existing_urls = {
            # (url.MD5.lower(), url.VendorID): url for url in MaliciousURLs.query.all()
            (url.MD5.lower()): url for url in MaliciousURLs.query.all()
        }

        # Extract source names from URLs and validate them
        sources = [{"Name": record['VendorName'].strip()} for record in urls_data]
    
        validate_and_insert_sources(sources, ignore_existing_sources=True)
        
        # Get the source IDs for the vendors
        source_ids = get_source_ids([src["Name"] for src in sources])
        print("dour ::: ", source_ids)
        inserted_count = 0
        updated_count = 0

        # Process in batches
        for i in range(0, len(urls_data), batch_size):
            batch = urls_data[i:i + batch_size]
            new_urls = []
            new_urls_hash_set = set()
            for record in batch:
                normalized_url = record['URL'].strip().lower()
                # Parse the URL to extract the domain
                parsed_url = urlparse(normalized_url)
                domain = parsed_url.netloc  # Extract the netloc (domain) part of the URL

                # Convert URL to MD5
                md5_hash = hashlib.md5(normalized_url.encode('utf-8')).hexdigest()
                md5_hash_main_domain = hashlib.md5(domain.encode('utf-8')).hexdigest()

                # Get the vendor ID from source_ids
                vendor_name = record['VendorName'].strip()
                vendor = source_ids.get(vendor_name)

                # Check if the MD5 exists in the database
                # key = (md5_hash, vendor)
                key = (md5_hash)

                # print("key :: ",key)
                if md5_hash in existing_urls or md5_hash in new_urls_hash_set:
                    # Update EntryStatus and other fields for existing MD5
                    if md5_hash in existing_urls:
                        existing_urls[md5_hash].EntryStatus = record['EntryStatus']
                        existing_urls[md5_hash].Score = record.get('Score', 0.0)
                        existing_urls[md5_hash].VendorID = vendor
                        updated_count += 1
                    # Skip duplicates in the current batch
                    continue
                else:
                    # Add MD5 to Redis cache
                    new_urls_hash_set.add(md5_hash)
                    # Create a new MaliciousURLs record
                    new_urls.append(MaliciousURLs(
                        URL=record['URL'].strip(),
                        VendorID=vendor,
                        EntryStatus=record['EntryStatus'],
                        Score=record.get('Score', 0),  # Default score to 0 if not provided
                        MD5=md5_hash,  # Store MD5 hash
                        MainDomain = domain,
                        Main_domain_MD5 = md5_hash_main_domain
                    ))
                    inserted_count += 1
                redis_service.add_to_malicious_url_cache(md5_hash, md5_hash_main_domain, record['EntryStatus'])
            # print("new_urls :: ", new_urls)

            # Bulk insert new records in the batch
            if new_urls:
                db.session.bulk_save_objects(new_urls)

            # Commit the batch
            db.session.commit()

        print(f"Processing completed. Inserted: {inserted_count}, Updated: {updated_count}")
        return {
            "message": f"Processing completed. Inserted: {inserted_count}, Updated: {updated_count}"
        }, True
    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        print(f"An error occurred: {str(e)}")
        return {"error": f"An error occurred: {str(e)}"}, False
