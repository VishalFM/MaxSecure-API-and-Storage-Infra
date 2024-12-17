from app.models.model import Hits, Signature
from app.extensions import db

def bulk_insert_hits(hits_data, batch_size=10000):
    try:
        signature_values = [record['Signature'] for record in hits_data]
        signatures = db.session.query(Signature.ID, Signature.Signature).filter(
            Signature.Signature.in_(signature_values)
        ).all()
        signature_map = {sig.Signature: sig.ID for sig in signatures}
        records = []
        for record in hits_data:
            signature_value = record['Signature']
            signature_id = signature_map.get(signature_value)
            if signature_id:
                records.append({
                    'SignatureTableID': signature_id,
                    'Hits': record['Hits']
                })
            else:
                raise ValueError(f"Signature '{signature_value}' not found in the Signature table.")
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            db.session.bulk_insert_mappings(Hits, batch)
        db.session.commit()
        return {"message": f"{len(hits_data)} hits successfully inserted."}, True
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}"}, False
