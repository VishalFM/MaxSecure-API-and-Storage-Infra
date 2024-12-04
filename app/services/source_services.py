from app.models.model import Source
from app.extensions import db

def insert_sources(sources):
    """
    Inserts multiple source records into the database in bulk.
    """
    try:
        print("here")
        # Step 1: Prepare the list of Source objects
        source_objects = [Source(Name=source['Name']) for source in sources]

        print("source_objects  --  ", source_objects)
        # Step 2: Bulk insert into the database
        validate_and_insert_sources(source_objects)
        # db.session.bulk_save_objects(source_objects)
        print("here")

        # Step 3: Commit the transaction
        db.session.commit()

        # Step 4: Return success message with the number of inserted records
        return {"message": f"{len(sources)} sources successfully inserted."}
    except Exception as e:
        # Step 5: Rollback in case of error and return an error message
        print("     error    ", str(e))
        db.session.rollback()
        return {"error": f"An error occurred while inserting the sources: {str(e)}"}
    

def validate_and_insert_sources(sources_data, ignore_existing_sources=False):
    """
    Validates and inserts new sources into the Source table if they do not already exist.
    Args:
        sources_data (list): List of sources to validate and insert.
        ignore_existing_sources (bool): If True, ignores existing sources.
    Returns:
        dict: Result of the validation and insertion.
    """
    try:
        sources_to_insert = []
        for source in sources_data:
            source_name = source.get('Name')

            if not source_name:
                continue  # Skip if there's no valid source name

            # Check if the source already exists
            existing_source = db.session.query(Source).filter(Source.Name == source_name).first()
            if existing_source:
                if not ignore_existing_sources:
                    return {"error": f"Source '{source_name}' already exists."}, False
            else:
                # If the source doesn't exist, prepare to insert
                sources_to_insert.append(Source(Name=source_name))

        if sources_to_insert:
            db.session.add_all(sources_to_insert)
            db.session.commit()

        return {"message": f"{len(sources_to_insert)} sources successfully inserted."}, True

    except Exception as e:
        db.session.rollback()
        return {"error": f"An error occurred while validating sources: {str(e)}"}, False
