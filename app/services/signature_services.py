import threading
from datetime import datetime
from app.models.model import Signature, FileType, Source, SpywareCategory, SpywareName
from app.extensions import db
from app.services.redis_services import RedisService, update_redis_cache_in_thread
from app.services.file_type_services import validate_and_insert_file_types, get_file_type_ids
from app.services.source_services import validate_and_insert_sources, get_source_ids
from app.services.spyware_category_services import get_or_create_spyware_category
from app.services.spyware_name_services import get_or_create_spyware_name
from sqlalchemy.exc import IntegrityError

redis_service = RedisService()

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
        signature_map_white = {}
        signature_map_malware = {}
        response_data = [] 

        for record in valid_records:
            category_name, spyware_name = record["SpywareName"].split(".", 1)
            category_id = get_or_create_spyware_category(category_name)
            record['SpywareNameID'] = get_or_create_spyware_name(spyware_name, category_id)
            record["FileTypeID"] = file_type_ids.get(record["FileType"])
            record["SourceID"] = source_ids.get(record["Source"])
            record["SHA256"] = record.get("SHA256")
            record["OS"] = record.get("OS")

            if record["EntryStatus"] == 0:  # White Cache
                signature_map_white[record['Signature']] = f"{record['SpywareName']}|{record['SHA256']}|{record['Source']}"
            elif record["EntryStatus"] == 1:  # Malware Cache
                signature_map_malware[record['Signature']] = f"{record['SpywareName']}|{record['SHA256']}|{record['Source']}"

        current_timestamp = datetime.now()
        inserted_count = 0
        updated_count = 0

        for record in valid_records:
            signature = record['Signature']
            entry_status = record['EntryStatus']
            spyware_name_id = record['SpywareNameID']
            source_id = record['SourceID']
            file_type_id = record['FileTypeID']
            hits_count = record.get('HitsCount', 0)
            sha256 = record["SHA256"]
            os = record["OS"]

            # Try to find an existing Signature record by the Signature field
            existing_signature = db.session.query(Signature).filter_by(Signature=signature).first()

            if existing_signature:
                # If the record exists, update the necessary fields
                existing_signature.EntryStatus = entry_status
                existing_signature.SpywareNameID = spyware_name_id
                existing_signature.SourceID = source_id
                existing_signature.FileTypeID = file_type_id
                existing_signature.UpdateDate = current_timestamp
                existing_signature.HitsCount += hits_count  # Increment HitsCount
                existing_signature.SHA256 = sha256
                existing_signature.OS = os

                updated_count += 1
                response_data.append({
                    "Signature": signature,
                    "Status": "updated",
                    "Message": f"Signature '{signature}' was updated."
                })
            else:
                # If the record does not exist, create a new one (no need to specify InsertDate or UpdateDate)
                new_signature = Signature(
                    Signature=signature,
                    EntryStatus=entry_status,
                    SpywareNameID=spyware_name_id,
                    SourceID=source_id,
                    FileTypeID=file_type_id,
                    HitsCount=hits_count,
                    SHA256=sha256,
                    OS=os
                )
                db.session.add(new_signature)

                inserted_count += 1
                response_data.append({
                    "Signature": signature,
                    "Status": "inserted",
                    "Message": f"Signature '{signature}' was inserted."
                })

        db.session.commit()

        redis_service.save_to_redis(signature_map_white, signature_map_malware)

        return {
            "message": f"{inserted_count} signatures processed. {updated_count} updated.",
            "inserted_count": inserted_count,
            "updated_count": updated_count,
            "details": response_data
        }, True

    except IntegrityError as e:
        db.session.rollback()
        return {"error": f"Integrity error occurred: {str(e)}"}, False
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}"}, False

def delete_signatures(signatures):
    try:
        # Delete related hits from the "Hits" table
        delete_hits_query = db.text("""
            DELETE FROM "Hits" 
            WHERE "SignatureTableID" IN (
                SELECT "ID" FROM "Signature" WHERE "Signature" = ANY(:signatures)
            )
        """)
        db.session.execute(delete_hits_query, {'signatures': signatures})

        # Delete signatures from the "Signature" table
        delete_signatures_query = db.text("""
            DELETE FROM "Signature" WHERE "Signature" = ANY(:signatures)
        """)
        db.session.execute(delete_signatures_query, {'signatures': signatures})

        # Delete signatures from Redis
        for signature in signatures:
            redis_service.delete_from_redis(signature)

        db.session.commit()
        return {"message": f"Signatures {signatures} deleted successfully."}, True

    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred while deleting signatures: {str(e)}"}, False
 
def update_signature(signature, signature_data):
    try:
        existing_signature = db.session.execute(db.text("""
            SELECT s."SHA256"
            FROM "Signature" s
            JOIN "SpywareName" sn ON sn."ID" = s."SpywareNameID"
            WHERE s."Signature" = :signature
        """), {'signature': signature}).fetchone()

        if not existing_signature:
            return {"error": f"Signature '{signature}' not found."}, False
        
        category_name, spyware_name = signature_data['SpywareName'].split(".", 1)
        category_id = get_or_create_spyware_category(category_name)
        spyware_name_id = get_or_create_spyware_name(spyware_name, category_id)

        db.session.execute(db.text("""
            UPDATE "Signature"
            SET "EntryStatus" = :entry_status,
                "SpywareNameID" = :spyware_name_id,
                "UpdateDate" = :update_date
            WHERE "Signature" = :signature
        """), {
            'signature': signature,
            'entry_status': signature_data['EntryStatus'],
            'spyware_name_id': spyware_name_id,
            'update_date': datetime.now()
        })

        redis_data = {f"{signature}|{signature_data['EntryStatus']}": f"{signature_data['SpywareName']}|{existing_signature[0]}"}
        redis_service.save_to_redis(redis_data)

        db.session.commit()
        return {"message": f"Signature '{signature}' updated successfully."}, True

    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred while updating the signature: {str(e)}"}, False

def search_signatures_service(signature=None):
    try:
        if not signature or not isinstance(signature, list):
            return {"status": "error", "message": "The 'signature' parameter is required and must be a list"}, 400

        query = db.session.query(Signature.Signature, Signature.EntryStatus, SpywareName.Name).join(SpywareName).filter(
            Signature.Signature.in_(signature)
        )

        results = query.all()

        found_signatures = {result.Signature for result in results}

        missing_signatures = list(set(signature) - found_signatures)

        # Formatted results for found signatures
        formatted_results = [
            {
                "Signature": result.Signature,
                "EntryStatus": result.EntryStatus,
                "SpywareName": result.Name if result.EntryStatus != 0 else None
            }
            for result in results
        ]

        # Add missing signatures with EntryStatus -1 and SpywareName None
        missing_results = [
            {
                "Signature": sig,
                "EntryStatus": -1,
                "SpywareName": None
            }
            for sig in missing_signatures
        ]

        # Merging both found and missing results
        all_results = formatted_results + missing_results

        response = {
            "status": "success",
            "data": all_results
        }

        if not all_results:
            response["message"] = "No signatures found"

        return response, 200

    except Exception as e:
        return {"status": "error", "message": f"An error occurred: {str(e)}"}, 500
