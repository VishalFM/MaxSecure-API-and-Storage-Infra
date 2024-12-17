from sqlalchemy import func
from app.extensions import db
from app.models.model import FileType
from app.utils.file_type_validator import validate_file_types

def insert_file_types(file_type_names):
    result_status = []
    new_file_types = [FileType(Type=file_type_name.strip().lower()) for file_type_name in file_type_names]

    try:
        for file_type in new_file_types:
            existing_file_type = FileType.query.filter(FileType.Type.ilike(file_type.Type)).first()

            if existing_file_type:
                result_status.append({"file_type": file_type.Type, "status": "already exists"})
            else:
                db.session.add(file_type)
                result_status.append({"file_type": file_type.Type, "status": "to be inserted"})

        db.session.commit()

        for status in result_status:
            if status["status"] == "to be inserted":
                status["status"] = "inserted"

        return {"message": f"Operation completed. {len(result_status)} file types processed."}, result_status

    except Exception as e:
        db.session.rollback()
        return {"error": f"Failed to insert file types: {str(e)}"}, result_status

def validate_and_insert_file_types(data, ignore_existing_file_types = False):
    errors, valid_file_types = validate_file_types(data, ignore_existing_file_types)
    if errors:
        return {"error": errors}, None

    result_message, status = insert_file_types(valid_file_types)

    return {"message": result_message}, status

def get_file_type_ids(file_types):
    file_types_casefolded = [file_type.casefold() for file_type in file_types]
    file_type_name_map = {file_type.casefold(): file_type for file_type in file_types}

    return {
        file_type_name_map[record.Type.casefold()]: record.ID
        for record in db.session.query(FileType)
        .filter(db.func.lower(FileType.Type).in_(file_types_casefolded))
        .all()
    }
