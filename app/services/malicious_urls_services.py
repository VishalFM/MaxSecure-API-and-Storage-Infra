from app.models.model import MaliciousURLs, Source
from app.extensions import db
# from app.services.source_services import get_or_create_source

def get_or_create_source(source_name):
    """
    Retrieves or creates a source record in the database.

    Args:
        source_name (str): The source name to lookup or create.

    Returns:
        Source: The existing or newly created Source record.
    """
    source_record = db.session.query(Source).filter(Source.Name == source_name).first()
    if not source_record:
        source_record = Source(Name=source_name)
        db.session.add(source_record)
        db.session.flush()
    return source_record

def bulk_insert_malicious_urls(urls_data, batch_size=10000):
    """
    Handles bulk insertion or updating of malicious URLs into the database with case-insensitive handling.
    
    Args:
        urls_data (list): A list of dictionaries, each containing `URL`, `VendorName`, and `EntryStatus`.
        batch_size (int): Number of records to process per batch.
        
    Returns:
        dict: Summary of the insertion results.
    """
    try:
        # Preload all existing vendors and malicious URLs into memory
        vendors = {vendor.Name.lower(): vendor.ID for vendor in Source.query.all()}  # Case-insensitive vendor names
        existing_urls = {
            (url.URL.lower(), url.VendorID): url for url in MaliciousURLs.query.all()  # Case-insensitive URLs
        }

        inserted_count = 0
        updated_count = 0

        # Process in batches
        for i in range(0, len(urls_data), batch_size):
            batch = urls_data[i:i + batch_size]
            new_urls = []
            for record in batch:
                # Normalize URL and VendorName to lowercase
                normalized_url = record['URL'].strip().lower()
                normalized_vendor_name = record['VendorName'].strip().lower()

                # Use get_or_create_source to retrieve or create the vendor
                vendor = vendors.get(normalized_vendor_name)
                if not vendor:
                    source = get_or_create_source(record['VendorName'].strip())
                    vendors[normalized_vendor_name] = source.ID  # Cache the newly created vendor
                    vendor = source.ID

                # Check if the URL exists for the vendor
                key = (normalized_url, vendor)
                if key in existing_urls:
                    # Update EntryStatus for existing URL
                    existing_urls[key].EntryStatus = record['EntryStatus']
                    updated_count += 1
                else:
                    # Create a new MaliciousURLs record
                    new_urls.append(MaliciousURLs(
                        URL=normalized_url,  # Store the normalized URL
                        VendorID=vendor,
                        EntryStatus=record['EntryStatus']
                    ))
                    inserted_count += 1

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
