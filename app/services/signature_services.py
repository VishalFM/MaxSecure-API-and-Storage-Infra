import threading
from datetime import datetime
from app.models.model import Signature, FileType, Source, SpywareCategory, SpywareName
from app.extensions import db
from app.services.redis_services import update_redis_cache_in_thread
from app.services.file_type_services import validate_and_insert_file_types, get_file_type_ids
from app.services.source_services import validate_and_insert_sources, get_source_ids
from app.services.spyware_category_services import get_or_create_spyware_category
from app.services.spyware_name_services import get_or_create_spyware_name

def process_and_validate_records(signatures_data):
    required_fields = {'Signature', 'EntryStatus', 'SpywareName', 'Source', 'FileType', 'SHA256', 'OS'}
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
    file_type_record = db.session.query(FileType).filter(FileType.Type == file_type).first()
    if not file_type_record:
        file_type_record = FileType(Type=file_type)
        db.session.add(file_type_record)
        db.session.flush()
    return file_type_record


def get_or_create_source(source_name):
    source_record = db.session.query(Source).filter(Source.Name == source_name).first()
    if not source_record:
        source_record = Source(Name=source_name)
        db.session.add(source_record)
        db.session.flush()
    return source_record

def bulk_insert_signatures(signatures_data):
    try:
        valid_records, file_types_to_validate, sources_to_validate, error = process_and_validate_records(signatures_data)
        if error:
            return error, False
        
        result_file = validate_and_insert_file_types(file_types_to_validate, ignore_existing_file_types=True)
        if result_file and "error" in result_file[0] and result_file[0]["error"]: 
            return result_file[0]["error"], False        
        
        result_source = validate_and_insert_sources(sources_to_validate, ignore_existing_sources=True)
        if result_source and "error" in result_source[0] and result_source[0]["error"]: 
            return result_source[0]["error"], False      

        file_type_ids = get_file_type_ids([ft["Type"] for ft in file_types_to_validate])
        source_ids = get_source_ids([src["Name"] for src in sources_to_validate])

        for record in valid_records:
            category_name, spyware_name = record["SpywareName"].split(".", 1)
            category_id = get_or_create_spyware_category(category_name)
            record['SpywareNameID'] = get_or_create_spyware_name(spyware_name, category_id)
            record["FileTypeID"] = file_type_ids.get(record["FileType"])
            record["SourceID"] = source_ids.get(record["Source"])
            record["SHA256"] = record.get("SHA256")
            record["OS"] = record.get("OS")

            redis_thread = threading.Thread(target=update_redis_cache_in_thread, args=({
                "Signature": record['Signature'],
                "EntryStatus": record['EntryStatus'],
                "SpywareNameID": record['SpywareNameID'],
                "SourceID": record['SourceID'],
                "FileTypeID": record['FileTypeID'],
                "HitsCount": record.get('HitsCount', 0),
                "SpywareNameAndCategory": record['SpywareName'],
                "SHA256": record["SHA256"],  
                "OS": record["OS"]  
            },))
            redis_thread.start()

        insert_query = db.text("""
            INSERT INTO "Signature" ("Signature", "EntryStatus", "SpywareNameID", "SourceID", "FileTypeID", "InsertDate", "UpdateDate", "HitsCount", "SHA256", "OS")
            VALUES (:Signature, :EntryStatus, :SpywareNameID, :SourceID, :FileTypeID, :InsertDate, :UpdateDate, :HitsCount, :SHA256, :OS)  
            ON CONFLICT("Signature") 
            DO UPDATE SET
                "EntryStatus" = EXCLUDED."EntryStatus",
                "SpywareNameID" = EXCLUDED."SpywareNameID",
                "SourceID" = EXCLUDED."SourceID",
                "FileTypeID" = EXCLUDED."FileTypeID",
                "UpdateDate" = EXCLUDED."UpdateDate",
                "HitsCount" = "Signature"."HitsCount" + EXCLUDED."HitsCount",
                "SHA256" = EXCLUDED."SHA256",  
                "OS" = EXCLUDED."OS";  
        """)

        current_timestamp = datetime.now()
        batch_size = 10000
        inserted_count = 0

        for i in range(0, len(valid_records), batch_size):
            batch = valid_records[i:i + batch_size]
            batch_data = [{
                "Signature": record['Signature'],
                "EntryStatus": record['EntryStatus'],
                "SpywareNameID": record['SpywareNameID'],
                "SourceID": record['SourceID'],
                "FileTypeID": record['FileTypeID'],
                "InsertDate": current_timestamp,
                "UpdateDate": current_timestamp,
                "HitsCount": record.get('HitsCount', 0),
                "SHA256": record["SHA256"],  
                "OS": record["OS"]  
            } for record in batch]

            db.session.execute(insert_query, batch_data)
            db.session.flush()
            inserted_count += len(batch)

        db.session.commit()
        return {"message": f"{inserted_count} signatures successfully processed.", "inserted_count": inserted_count}, True

    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}", "inserted_count": 0}, False
