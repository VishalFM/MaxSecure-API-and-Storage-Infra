import threading
from datetime import datetime
from app.models.model import Signature, FileType, Source, SpywareCategory, SpywareName
from app.extensions import db
from app.services.redis_services import update_redis_cache_in_thread
from app.services.file_type_services import validate_and_insert_file_types
from app.services.source_services import validate_and_insert_sources

def process_and_validate_records(signatures_data):
    """
    Validates and filters signature records, prepares file types and sources for validation.
    
    Args:
        signatures_data (list): List of signature records to process.

    Returns:
        tuple: Valid records, file types to validate, sources to validate, error message (if any).
    """
    required_fields = {'Signature', 'EntryStatus', 'SpywareNameID', 'Source', 'FileType'}
    valid_records = []
    file_types_to_validate = []
    sources_to_validate = []
    
    for record in signatures_data:
        if required_fields.issubset(record.keys()) and all(record.get(field) is not None for field in required_fields):
            valid_records.append(record)
            file_types_to_validate.append({"Type": record["FileType"]})
            sources_to_validate.append({"Name": record["Source"]})

    if not valid_records:
        return [], [], [], {"error": "No valid records found for insertion."}

    return valid_records, file_types_to_validate, sources_to_validate, None


def get_or_create_file_type(file_type):
    """
    Retrieves or creates a file type record in the database.

    Args:
        file_type (str): The file type to lookup or create.

    Returns:
        FileType: The existing or newly created FileType record.
    """
    file_type_record = db.session.query(FileType).filter(FileType.Type == file_type).first()
    if not file_type_record:
        file_type_record = FileType(Type=file_type)
        db.session.add(file_type_record)
        db.session.flush()
    return file_type_record


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


def bulk_insert_signatures(signatures_data):
    """
    Handles the bulk insertion of signature data with file type and source lookup and creation.
    
    Args:
        signatures_data (list): List of signature records to insert.
        
    Returns:
        dict: Summary of insertion results.
    """
    try:
        # Step 1: Process and validate records
        valid_records, file_types_to_validate, sources_to_validate, error = process_and_validate_records(signatures_data)
        if error:
            return error, False

        # Step 2: Validate and insert file types
        validation_result = validate_and_insert_file_types(file_types_to_validate, ignore_existing_file_types=True)
        if isinstance(validation_result, dict) and validation_result.get("error"):
            return validation_result, False

        # Step 3: Validate and insert sources
        validation_result = validate_and_insert_sources(sources_to_validate, ignore_existing_sources=True)
        if isinstance(validation_result, dict) and validation_result.get("error"):
            return validation_result, False

        # Step 4: Map FileType and Source to their respective IDs and prepare for insertion
        inserted_count = 0
        batch_size = 10000
        current_timestamp = datetime.now()

        for i in range(0, len(valid_records), batch_size):
            batch = valid_records[i:i + batch_size]

            for record in batch:
                # Handle FileType mapping
                file_type_record = get_or_create_file_type(record["FileType"])
                record["FileTypeID"] = file_type_record.ID

                # Handle Source mapping
                source_record = get_or_create_source(record["Source"])
                record["SourceID"] = source_record.ID

                # print("db.session.query(SpywareName).filter_by(ID=record['SpywareNameID']).join(SpywareCategory).first() ::", db.session.query(SpywareName).filter_by(ID=record['SpywareNameID']).join(SpywareCategory).first())
                # # Step 5: Use threading to update Redis cache concurrently
                # redis_thread = threading.Thread(target=update_redis_cache_in_thread, args=({
                #     "Signature": record['Signature'],
                #     "EntryStatus": record['EntryStatus'],
                #     "SpywareNameID": record['SpywareNameID'],
                #     "SourceID": record['SourceID'],
                #     "FileTypeID": record['FileTypeID'],
                #     "HitsCount": record.get('HitsCount', 0),
                #     "SpywareNameAndCategory": db.session.query(SpywareName).filter_by(ID=record['SpywareNameID']).join(SpywareCategory).first()
                # },))
                # redis_thread.start()


                spyware_name_entry = db.session.query(SpywareName).filter_by(ID=record['SpywareNameID']).join(SpywareCategory).first()
    
                if spyware_name_entry:
                    # Concatenate SpywareCategory and SpywareName as a string
                    spyware_category_name = f"{spyware_name_entry.spyware_category.Category}.{spyware_name_entry.Name}"
                else:
                    spyware_category_name = "Unknown"  # Set a default value if not found

                # Now, add the concatenated SpywareName and SpywareCategory to the record
                record['SpywareNameAndCategory'] = spyware_category_name

                # Start the threading with the updated record
                redis_thread = threading.Thread(target=update_redis_cache_in_thread, args=({
                    "Signature": record['Signature'],
                    "EntryStatus": record['EntryStatus'],
                    "SpywareNameID": record['SpywareNameID'],
                    "SourceID": record['SourceID'],
                    "FileTypeID": record['FileTypeID'],
                    "HitsCount": record.get('HitsCount', 0),
                    "SpywareNameAndCategory": record['SpywareNameAndCategory']
                },))
                redis_thread.start()



            # Bulk Insert or Update in batches with conflict handling
            insert_query = db.text("""
                INSERT INTO "Signature" ("Signature", "EntryStatus", "SpywareNameID", "SourceID", "FileTypeID", "InsertDate", "UpdateDate", "HitsCount")
                VALUES (:Signature, :EntryStatus, :SpywareNameID, :SourceID, :FileTypeID, :InsertDate, :UpdateDate, :HitsCount)
                ON CONFLICT("Signature") 
                DO UPDATE SET
                    "EntryStatus" = EXCLUDED."EntryStatus",
                    "SpywareNameID" = EXCLUDED."SpywareNameID",
                    "SourceID" = EXCLUDED."SourceID",
                    "FileTypeID" = EXCLUDED."FileTypeID",
                    "UpdateDate" = EXCLUDED."UpdateDate",
                    "HitsCount" = EXCLUDED."HitsCount";
            """)

            batch_data = [
                {
                    "Signature": record['Signature'],
                    "EntryStatus": record['EntryStatus'],
                    "SpywareNameID": record['SpywareNameID'],
                    "SourceID": record['SourceID'],
                    "FileTypeID": record['FileTypeID'],
                    "InsertDate": current_timestamp,
                    "UpdateDate": current_timestamp,
                    "HitsCount": record.get('HitsCount', 0)
                }
                for record in batch
            ]

            db.session.execute(insert_query, batch_data)
            db.session.flush()
            inserted_count += len(batch)

        db.session.commit()
        return {"message": f"{inserted_count} signatures successfully processed.", "inserted_count": inserted_count}, True

    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}", "inserted_count": 0}, False
