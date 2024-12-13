from sqlalchemy import func
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
        # print("Source function startedchgchg :: sources_data :: ", sources_data)
        sources_to_insert = []
        already_processed = set()  

        for source in sources_data:
            source_name = source.get('Name')

            if not source_name:
                continue  # Skip if there's no valid source name

            # Normalize the source name for case-insensitive comparison
            normalized_source_name = source_name.casefold()
             
            if normalized_source_name in already_processed:
                continue  # Skip if the source is already processed in this batch


            # Check if the source already exists (case-insensitively)
            existing_source = db.session.query(Source).filter(
                func.lower(Source.Name) == normalized_source_name
            ).first()

            if existing_source:
                if not ignore_existing_sources:
                    return {"error": f"Source '{source_name}' already exists."}, False
            else:
                # If the source doesn't exist, prepare to insert
                sources_to_insert.append(Source(Name=source_name))
                already_processed.add(normalized_source_name) 

        # print("sources_to_insert ::", sources_to_insert)

        if sources_to_insert:
            db.session.add_all(sources_to_insert)
            db.session.commit()
        print("sources_to_insert inserted  ::", sources_to_insert)

        return {"message": f"{len(sources_to_insert)} sources successfully inserted."}, True

    except Exception as e:
        db.session.rollback()
        print("error :: ", str(e))
        return {"error": f"An error occurred while validating sources: {str(e)}"}, False

def get_source_ids(sources):
    """
    Retrieves source IDs for the given source names.

    Args:
        sources (list): List of source name strings.

    Returns:
        dict: Mapping of source name strings to their IDs.
    """
    # print("sources :: ", sources)
    sources_casefolded = [source.casefold() for source in sources]
    source_name_map = {source.casefold(): source for source in sources}
    # print("sources_casefolded :: ",sources_casefolded)
    # print("source_name_map :: ", source_name_map)
    return {
        source_name_map[record.Name.casefold()]: record.ID
        for record in db.session.query(Source)
        .filter(db.func.lower(Source.Name).in_(sources_casefolded))
        .all()
    }
