from app.models.model import WhiteFileName, Signature
from app.extensions import db
from datetime import datetime

def bulk_insert_white_file_names(white_file_names_data):
    try:
        required_fields = {'Name', 'Signature'}
        valid_records = []

        for record in white_file_names_data:
            if required_fields.issubset(record.keys()) and all(record.get(field) for field in required_fields):
                valid_records.append(record)
                signature_value = record["Signature"]

                signature = Signature.query.filter_by(Signature=signature_value).first()

                if not signature:
                    return {"error": f"Signature '{signature_value}' not found."}, False

                record["SignatureTableID"] = signature.ID

        if not valid_records:
            return {"error": "No valid records found for insertion.", "inserted_count": 0}, False

        batch_size = 10000
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
                    "SignatureTableID": record['SignatureTableID'],
                }
                for record in batch
            ]

            db.session.execute(insert_query, batch_data)
            db.session.flush()
            inserted_count += len(batch)

        db.session.commit()
        return {"message": f"{inserted_count} white file names successfully inserted.", "inserted_count": inserted_count}, True

    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}", "inserted_count": 0}, False
