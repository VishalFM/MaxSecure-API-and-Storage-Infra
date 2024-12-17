from sqlalchemy import func
from app.extensions import db
from app.models.model import FileType
from app.utils.file_type_validator import validate_file_types

def insert_file_types(file_type_names):
    """
    Insert validated file types into the database.
    """
    result_status = []
    # Normalize to lowercase for both incoming request and database comparisons
    new_file_types = [FileType(Type=file_type_name.strip().lower()) for file_type_name in file_type_names]
    
    try:
        # Iterate over the file types to insert
        for file_type in new_file_types:
            # Check if the file type already exists before inserting (case-insensitive comparison)
            existing_file_type = FileType.query.filter(FileType.Type.ilike(file_type.Type)).first()
            
            if existing_file_type:
                result_status.append({"file_type": file_type.Type, "status": "already exists"})
            else:
                db.session.add(file_type)
                result_status.append({"file_type": file_type.Type, "status": "to be inserted"})
        
        # Commit all the valid file types to the session at once
        db.session.commit()

        # Final status update to inserted for those added to session
        for status in result_status:
            if status["status"] == "to be inserted":
                status["status"] = "inserted"
        
        return {"message": f"Operation completed. {len(result_status)} file types processed."}, result_status

    except Exception as e:
        db.session.rollback()
        return {"error": f"Failed to insert file types: {str(e)}"}, result_status


def validate_and_insert_file_types(data, ignore_existing_file_types = False):
    """
    Combined logic for validating and inserting file types.
    """
    # Validate the file types and get errors and valid ones
    errors, valid_file_types = validate_file_types(data, ignore_existing_file_types)
    print("errors > ", errors)
    if errors:
        print("here ...")
        return {"error": errors}, None  # If there are errors, return them

    # Insert valid file types and get status for each one
    result_message, status = insert_file_types(valid_file_types)
    
    return {"message": result_message}, status

def get_file_type_ids(file_types):
    """
    Retrieves file type IDs for the given file types.

    Args:
        file_types (list): List of file type strings.

    Returns:
        dict: Mapping of file type strings to their IDs.
    """
    file_types_casefolded = [file_type.casefold() for file_type in file_types]
    file_type_name_map = {file_type.casefold(): file_type for file_type in file_types}
    
    return {
        file_type_name_map[record.Type.casefold()]: record.ID
        for record in db.session.query(FileType)
        .filter(db.func.lower(FileType.Type).in_(file_types_casefolded))
        .all()
    }