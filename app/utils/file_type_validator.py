import re
from app.models.model import FileType

def validate_file_type(file_type_name):
    if not file_type_name or not isinstance(file_type_name, str) or len(file_type_name.strip()) == 0:
        return f"Invalid file type: '{file_type_name}'. File type must be a non-empty string."
    
    return None

def validate_file_types(file_types, ignore_existing_file_types=False):
    if not file_types or not isinstance(file_types, list):
        return {"error": "Invalid input format. Expected a 'file_types' list."}, None

    errors = []
    valid_file_types = []
    for item in file_types:
        file_type_name = item.get('Type')
        error = validate_file_type(file_type_name)
        if error:
            if "already exists" in error and ignore_existing_file_types:
                continue
            errors.append(error)
        else:
            valid_file_types.append(file_type_name.strip())
    
    if errors:
        return {"error": errors}, None
    return None, valid_file_types
