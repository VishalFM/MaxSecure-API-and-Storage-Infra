import hashlib
from urllib.parse import urlparse
from app.models.model import MaliciousURLs, Source
from app.extensions import db
from app.services.source_services import get_source_ids, get_source_name_by_id, validate_and_insert_sources
from app.services.redis_services import RedisService
from app.utils.parse_url import get_md5_from_url

redis_service = RedisService()

def bulk_insert_malicious_urls(urls_data, batch_size=10000):
    try:
        existing_pairs = {
            (url.MD5.lower(), url.VendorID): url for url in db.session.query(
                MaliciousURLs.MD5, MaliciousURLs.VendorID, MaliciousURLs.EntryStatus, MaliciousURLs.Score
            ).all()
        }
        sources = [{"Name": record['VendorName'].strip()} for record in urls_data]
        validate_and_insert_sources(sources, ignore_existing_sources=True)
        source_ids = get_source_ids([src["Name"] for src in sources])
        print("here")
        inserted_count = updated_count = 0
        malicious_cache, domain_cache = [], []
        new_urls = []

        print("here")
        for i in range(0, len(urls_data), batch_size):
            batch = urls_data[i:i + batch_size]
            new_urls.clear()

            for record in batch:
                vendor_name = record['VendorName'].strip()
                vendor_id = source_ids.get(vendor_name)
                normalized_url = record['URL'].strip().lower()
                parsed_url = urlparse(normalized_url)   
                domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
                md5_url, md5_domain = get_md5_from_url(normalized_url), get_md5_from_url(domain)
                cache_value = f"{record['EntryStatus']}|{record.get('Score', 0.0)}|{vendor_name}"

                malicious_cache.append((md5_url, cache_value))
                domain_cache.append((md5_domain, cache_value))
                key = (md5_url, vendor_id)
                print("key > ", key)
                if key in existing_pairs:
                    print("existing_pairs[key] > ", existing_pairs[key])
                    existing = db.session.query(MaliciousURLs).filter_by(MD5=md5_url, VendorID=vendor_id).first() # existing_pairs[key]
                    if existing.EntryStatus != record['EntryStatus'] or existing.Score != record.get('Score', 0.0):
                        existing.EntryStatus = int(record['EntryStatus'])
                        existing.Score = float(record.get('Score', 0.0))
                        updated_count += 1
                else:
                    new_urls.append(MaliciousURLs(
                        URL=record['URL'].strip(),
                        VendorID=vendor_id,
                        EntryStatus=record['EntryStatus'],
                        Score=record.get('Score', 0.0),
                        MD5=md5_url,
                        MainDomain=domain,
                        Main_domain_MD5=md5_domain
                    ))
                    inserted_count += 1

            if new_urls:
                db.session.bulk_save_objects(new_urls)
            db.session.commit()
            print("here")
            redis_service.bulk_insert_cache(malicious_cache, "malicious_url")
            redis_service.bulk_insert_cache(domain_cache, "main_domain_url")

            malicious_cache.clear()
            domain_cache.clear()
        print("here")

        return {
            "message": f"Processing completed. Inserted: {inserted_count}, Updated: {updated_count}"
        }, True
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}"}, False

def bulk_delete_malicious_urls(md5_list, batch_size=10000):
    try:
        deleted_count = 0

        for i in range(0, len(md5_list), batch_size):
            batch = md5_list[i:i + batch_size]

            records_to_delete = db.session.query(MaliciousURLs).filter(
                MaliciousURLs.MD5.in_(batch)
            ).all()

            for record in records_to_delete:
                db.session.delete(record)
                deleted_count += 1

            db.session.commit()

        return {"message": f"Processing completed. Deleted: {deleted_count}"}, True
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}"}, False

def search_malicious_urls_service(url=None, md5=None, main_domain=None, main_domain_md5=None, vendor=None, page=1, per_page=100):
    try:
        query = db.session.query(MaliciousURLs)

        if url:
            query = query.filter(MaliciousURLs.URL.ilike(f'%{url.strip().lower()}%'))
        if md5:
            query = query.filter(MaliciousURLs.MD5.ilike(f'%{md5.strip().lower()}%'))
        if main_domain:
            query = query.filter(MaliciousURLs.MainDomain.ilike(f'%{main_domain.strip().lower()}%'))
        if main_domain_md5:
            query = query.filter(MaliciousURLs.Main_domain_MD5.ilike(f'%{main_domain_md5.strip().lower()}%'))
        if vendor:
            source_id = get_source_ids([vendor.strip()]).get(vendor.strip())
            if source_id:
                query = query.filter(MaliciousURLs.VendorID == source_id)

        query = query.offset((page - 1) * per_page).limit(per_page)

        results = query.all()

        result_data = [
            {
                "URL": record.URL,
                "MD5": record.MD5,
                "MainDomain": record.MainDomain,
                "MainDomainMD5": record.Main_domain_MD5,
                "Vendor": get_source_name_by_id(record.VendorID),
                "EntryStatus": record.EntryStatus,
                "Score": record.Score
            }
            for record in results
        ]

        return {"malicious_urls": result_data}, True

    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}, False

def insert_malicious_url(record):
    try:
        # Normalize and prepare data
        vendor_name = record['VendorName'].strip()
        normalized_url = record['URL'].strip().lower()
        domain = urlparse(normalized_url).netloc
        md5_url = get_md5_from_url(normalized_url)
        md5_domain = get_md5_from_url(domain)
        cache_value = f"{record['EntryStatus']}|{record.get('Score', 0.0)}|{vendor_name}"

        print("here")
        # Get Vendor ID
        validate_and_insert_sources([{"Name": vendor_name}], ignore_existing_sources=True)
        vendor_id = get_source_ids([vendor_name]).get(vendor_name)

        print("here")
        # Check existing record in the database
        existing = db.session.query(MaliciousURLs).filter_by(MD5=md5_url, VendorID=vendor_id).first()
        if existing:
            if existing.EntryStatus != record['EntryStatus'] or existing.Score != record.get('Score', 0.0):
                existing.EntryStatus = record['EntryStatus']
                existing.Score = record.get('Score', 0.0)
        else:
            new_url = MaliciousURLs(
                URL=record['URL'].strip(),
                VendorID=vendor_id,
                EntryStatus=record['EntryStatus'],
                Score=record.get('Score', 0.0),
                MD5=md5_url,
                MainDomain=domain,
                Main_domain_MD5=md5_domain
            )
            db.session.add(new_url)

        # Commit the database transaction
        db.session.commit()
        print("here")

        print("inserted into pg now inserting into redis")
        # Insert into Redis
        redis_service.bulk_insert_cache([(md5_url, cache_value)], "malicious_url")
        print(" inserted into malicisous uel redis")

        redis_service.bulk_insert_cache([(md5_domain, cache_value)], "main_domain_url")
        print(" inserted into main donmain url redis")

        return {"message": "Record inserted/updated successfully"}, True
    except Exception as e:
        print("erro : ",e)
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}"}, False

