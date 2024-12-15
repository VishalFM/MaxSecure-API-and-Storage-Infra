import hashlib
from urllib.parse import urlparse
from app.models.model import MaliciousURLs, Source
from app.extensions import db
from app.services.source_services import get_source_ids, validate_and_insert_sources
from app.services.redis_services import RedisService
from app.utils.parse_url import get_md5_from_url

redis_service = RedisService()

def bulk_insert_malicious_urls(urls_data, batch_size=10000):
    try:
        # Preload all existing vendors and malicious URLs into memory
        # vendors = {vendor.Name.lower(): vendor.ID for vendor in Source.query.all()}
        existing_pairs = {
            (url.MD5.lower(), url.VendorID): url for url in MaliciousURLs.query.all()
        }

        # Extract source names from URLs and validate them
        sources = [{"Name": record['VendorName'].strip()} for record in urls_data]
    
        validate_and_insert_sources(sources, ignore_existing_sources=True)
        
        # Get the source IDs for the vendors
        source_ids = get_source_ids([src["Name"] for src in sources])
        inserted_count = 0
        updated_count = 0
        
        # Initialize cache data storage
        malicious_url_cache_data = []
        main_domain_url_cache_data = []
        
        # Process in batches
        for i in range(0, len(urls_data), batch_size):
            print("in for loop ")
            batch = urls_data[i:i + batch_size]
            new_urls = []
            new_urls_hash_set = set() # Created this to skip if any MD5 already added from bulk

            for record in batch:
                print("in inner for loop ")
                # get vendor id
                vendor_name = record['VendorName'].strip()
                vendorId = source_ids.get(vendor_name)

                # getting url and md5
                normalized_url = record['URL'].strip().lower()
                parsed_url = urlparse(normalized_url)
                md5_hash = get_md5_from_url(normalized_url)
                domain = parsed_url.netloc  
                md5_hash_main_domain =  get_md5_from_url(domain)
                
                # Collect cache data for bulk insertion
                print("(md5_hash, record['EntryStatus']) > ", md5_hash, record['EntryStatus'])
                malicious_url_cache_data.append((md5_hash, record['EntryStatus']))
                main_domain_url_cache_data.append((md5_hash_main_domain, record['EntryStatus']))

                key = (md5_hash, vendorId)
                if key in existing_pairs or md5_hash in new_urls_hash_set:
                    if key in existing_pairs:
                        # Update EntryStatus and other fields for existing MD5
                        existing_pairs[key].EntryStatus = record['EntryStatus']
                        existing_pairs[key].Score = record.get('Score', 0.0)
                        updated_count += 1
                    continue # Skip duplicates in the current batch
                else:
                    new_urls_hash_set.add(md5_hash)
                    # add a new MaliciousURLs record
                    new_urls.append(MaliciousURLs(
                        URL=record['URL'].strip(),
                        VendorID=vendorId,
                        EntryStatus=record['EntryStatus'],
                        Score=record.get('Score', 0),  # Default score to 0 if not provided
                        MD5=md5_hash,  # Store MD5 hash
                        MainDomain = domain,
                        Main_domain_MD5 = md5_hash_main_domain
                    ))
                    inserted_count += 1
                

            if new_urls:
                db.session.bulk_save_objects(new_urls)
            db.session.commit()
            print("malicious_url_cache_data > ", malicious_url_cache_data)
            print("main_domain_url_cache_data > ", main_domain_url_cache_data)
            redis_service.bulk_insert_malicious_url_cache(malicious_url_cache_data)
            redis_service.bulk_insert_main_domain_url_cache(main_domain_url_cache_data)

        print(f"Processing completed. Inserted: {inserted_count}, Updated: {updated_count}")
        return {
            "message": f"Processing completed. Inserted: {inserted_count}, Updated: {updated_count}"
        }, True
    except Exception as e:
        db.session.rollback()  
        print(f"An error occurred: {str(e)}")
        return {"error": f"An error occurred: {str(e)}"}, False
