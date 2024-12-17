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
        existing_pairs = {
            (url.MD5.lower(), url.VendorID): url for url in MaliciousURLs.query.all()
        }
        sources = [{"Name": record['VendorName'].strip()} for record in urls_data]
        validate_and_insert_sources(sources, ignore_existing_sources=True)
        source_ids = get_source_ids([src["Name"] for src in sources])
        inserted_count = 0
        updated_count = 0
        malicious_url_cache_data = []
        main_domain_url_cache_data = []
        
        for i in range(0, len(urls_data), batch_size):
            batch = urls_data[i:i + batch_size]
            new_urls = []
            new_urls_hash_set = set()

            for record in batch:
                vendor_name = record['VendorName'].strip()
                vendorId = source_ids.get(vendor_name)
                normalized_url = record['URL'].strip().lower()
                parsed_url = urlparse(normalized_url)
                md5_hash = get_md5_from_url(normalized_url)
                domain = parsed_url.netloc 
                md5_hash_main_domain = get_md5_from_url(domain)
                malicious_url_cache_data.append((md5_hash, record['EntryStatus']))
                main_domain_url_cache_data.append((md5_hash_main_domain, record['EntryStatus']))
                key = (md5_hash, vendorId)

                if key in existing_pairs or md5_hash in new_urls_hash_set:
                    if key in existing_pairs:
                        existing_pairs[key].EntryStatus = record['EntryStatus']
                        existing_pairs[key].Score = record.get('Score', 0.0)
                        updated_count += 1
                    continue
                else:
                    new_urls_hash_set.add(md5_hash)
                    new_urls.append(MaliciousURLs(
                        URL=record['URL'].strip(),
                        VendorID=vendorId,
                        EntryStatus=record['EntryStatus'],
                        Score=record.get('Score', 0),
                        MD5=md5_hash,
                        MainDomain=domain,
                        Main_domain_MD5=md5_hash_main_domain
                    ))
                    inserted_count += 1

            if new_urls:
                db.session.bulk_save_objects(new_urls)
            db.session.commit()
            redis_service.bulk_insert_malicious_url_cache(malicious_url_cache_data)
            redis_service.bulk_insert_main_domain_url_cache(main_domain_url_cache_data)

        return {
            "message": f"Processing completed. Inserted: {inserted_count}, Updated: {updated_count}"
        }, True
    except Exception as e:
        db.session.rollback()  
        return {"error": f"An error occurred: {str(e)}"}, False
