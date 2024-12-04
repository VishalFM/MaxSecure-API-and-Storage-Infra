from app.models.model import MaliciousURLs
from app.extensions import db

def bulk_insert_malicious_urls(urls_data):
    """
    Handles bulk insertion of malicious URLs into the database.
    
    Args:
        urls_data (list): A list of dictionaries, each containing `URL`, `VendorID`, and `EntryStatus`.
        
    Returns:
        dict: Summary of the insertion results.
    """
    try:
        # Prepare the records for insertion
        records = [
            MaliciousURLs(URL=record['URL'], VendorID=record['VendorID'], EntryStatus=record['EntryStatus'])
            for record in urls_data
        ]
        
        # Bulk insert into the database
        db.session.bulk_save_objects(records)
        db.session.commit()

        return {"message": f"{len(urls_data)} URLs successfully inserted."}, True
    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred: {str(e)}"}, False
