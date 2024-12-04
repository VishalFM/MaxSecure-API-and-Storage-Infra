from app.models.model import Hits, Signature
from app.extensions import db

def bulk_insert_hits(hits_data, batch_size=10000):
    """
    Handles bulk insertion of hits data into the database using Signature value.
    
    Args:
        hits_data (list): A list of hits records, each containing Signature and Hits.
        batch_size (int): The number of records to insert per batch. Default is 10000.
        
    Returns:
        dict: Summary of the insertion results.
    """
    try:
        # Extract the signature values from the incoming data
        signature_values = [record['Signature'] for record in hits_data]

        # Fetch all matching Signature records in a single query
        signatures = db.session.query(Signature.ID, Signature.Signature).filter(
            Signature.Signature.in_(signature_values)
        ).all()

        # Create a dictionary mapping Signature value to Signature ID for fast lookup
        signature_map = {sig.Signature: sig.ID for sig in signatures}

        # Prepare the records for insertion
        records = []
        for record in hits_data:
            signature_value = record['Signature']
            # Check if the signature exists in the signature_map
            signature_id = signature_map.get(signature_value)

            if signature_id:
                # If Signature is found, add the record to the list
                records.append({
                    'SignatureTableID': signature_id,
                    'Hits': record['Hits']
                })
            else:
                # Handle the case where Signature does not exist (if necessary)
                raise ValueError(f"Signature '{signature_value}' not found in the Signature table.")

        # Perform bulk insert in batches
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            db.session.bulk_insert_mappings(Hits, batch)

        # Commit the transaction
        db.session.commit()

        return {"message": f"{len(hits_data)} hits successfully inserted."}, True
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}"}, False
