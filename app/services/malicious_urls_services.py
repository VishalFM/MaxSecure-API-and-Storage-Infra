import hashlib
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
            (url.MD5.lower(), url.VendorID): url for url in MaliciousURLs.query.all()
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
            for record in batch:
                normalized_url = record['URL'].strip().lower()

                # Convert URL to MD5
                md5_hash = hashlib.md5(normalized_url.encode('utf-8')).hexdigest()

                # Get the vendor ID from source_ids
                vendor_name = record['VendorName'].strip()
                vendor = source_ids.get(vendor_name)

                # Check if the MD5 exists in the database
                key = (md5_hash, vendor)

                # print("key :: ",key)
                if key in existing_urls:
                    # Update EntryStatus for existing MD5
                    existing_urls[key].EntryStatus = record['EntryStatus']
                    existing_urls[key].Score = record.get('Score', 0)  # Update the score if available
                    updated_count += 1
                else:
                    # Add MD5 to Redis cache
                    redis_service.add_to_malicious_url_cache(md5_hash, record['EntryStatus'])

                    # Create a new MaliciousURLs record
                    new_urls.append(MaliciousURLs(
                        URL=record['URL'].strip(),
                        VendorID=vendor,
                        EntryStatus=record['EntryStatus'],
                        Score=record.get('Score', 0),  # Default score to 0 if not provided
                        MD5=md5_hash  # Store MD5 hash
                    ))
                    inserted_count += 1
            # print("new_urls :: ", new_urls)

            # Bulk insert new records in the batch
            if new_urls:
                db.session.bulk_save_objects(new_urls)

            # Commit the batch
            db.session.commit()

        return {
            "message": f"Processing completed. Inserted: {inserted_count}, Updated: {updated_count}"
        }, True
    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        return {"error": f"An error occurred: {str(e)}"}, False
