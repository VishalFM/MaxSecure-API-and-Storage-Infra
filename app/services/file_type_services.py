from app.extensions import db
from app.models.model import FileType
from app.utils.file_type_validator import validate_file_types

def insert_file_types(file_type_names):
    """
    Insert validated file types into the database.
    """

    new_file_types = [FileType(Type=file_type_name.strip()) for file_type_name in file_type_names]
    try:
        print("in insert function ____try")
        db.session.add_all(new_file_types)
        db.session.commit()
        return {"message": f"{len(new_file_types)} file types successfully inserted."}, True
    except Exception as e:
        db.session.rollback()
        return {"error": f"Failed to insert file types: {str(e)}"}, False

def validate_and_insert_file_types(data, ignore_existing_file_types=False):
    """
    Combined logic for validating and inserting file types.
    """
    print("asdas")
    validation_result, valid_file_types = validate_file_types(data, ignore_existing_file_types)
    print("validation function completed : validation_result : ", validation_result)

    if validation_result:
        print("returning error msg")
        return validation_result  # Return validation errors

    print("Validated file types: ", valid_file_types)
    return insert_file_types(valid_file_types)  # Insert valid file types into DB
