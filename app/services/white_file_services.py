from app.models.model import WhiteFileName, Signature
from app.extensions import db

from datetime import datetime

def bulk_insert_white_file_names(white_file_names_data):
    try:
        # Step 1: Validate and filter records
        required_fields = {'Name', 'Signature'}
        valid_records = []

        # Fetch Signature data for mapping
        for record in white_file_names_data:
            if required_fields.issubset(record.keys()) and all(record.get(field) for field in required_fields):
                valid_records.append(record)
                signature_value = record["Signature"]

                # Use the relationship to find the Signature directly
                signature = Signature.query.filter_by(Signature=signature_value).first()

                if not signature:
                    return {"error": f"Signature '{signature_value}' not found."}, False

                # Map the actual Signature value to the corresponding Signature object
                record["SignatureTableID"] = signature.ID

        if not valid_records:
            return {"error": "No valid records found for insertion.", "inserted_count": 0}, False

        # Step 2: Perform the bulk insert
        batch_size = 10000  # Customize batch size based on system capacity
        inserted_count = 0

        for i in range(0, len(valid_records), batch_size):
            batch = valid_records[i:i + batch_size]

            insert_query = db.text("""
                INSERT INTO "WhiteFileName" ("Name", "SignatureTableID")
                VALUES (:Name, :SignatureTableID)
            """)

            batch_data = [
                {
                    "Name": record['Name'],
                    "SignatureTableID": record['SignatureTableID'],  # Using the SignatureTableID now
                }
                for record in batch
            ]

            # Execute the batch insert
            db.session.execute(insert_query, batch_data)
            db.session.flush()  # Flush after every batch
            inserted_count += len(batch)

        db.session.commit()  # Commit after processing all batches
        return {"message": f"{inserted_count} white file names successfully inserted.", "inserted_count": inserted_count}, True

    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}", "inserted_count": 0}, False
