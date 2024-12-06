import re
from app.models.model import FileType

def validate_file_type(file_type_name):
    """
    Validates a single file type.
    """
    if not file_type_name or not isinstance(file_type_name, str) or len(file_type_name.strip()) == 0:
        return f"Invalid file type: '{file_type_name}'. File type must be a non-empty string."
    print("1 completed")
    if not re.match(r'^\.[a-zA-Z0-9]+$', file_type_name.strip()):
        return f"Invalid file type format: '{file_type_name}'. Expected format: '.extension' (e.g., '.exe', '.bak')."
    
    print("2 completed")
    # existing_file_type = FileType.query.filter_by(Type=file_type_name.strip()).first()
    # if existing_file_type:
    #     return f"File type '{file_type_name}' already exists."
    
    print("all performed")
    return None  # No validation errors

def validate_file_types(file_types, ignore_existing_file_types=False):
    """
    Validates a list of file types.
    """
    print("faff ", file_types)
    if not file_types or not isinstance(file_types, list):
        return {"error": "Invalid input format. Expected a 'file_types' list."}, None

    print("if condition passed")
    errors = []
    valid_file_types = []
    for item in file_types:
        file_type_name = item.get('Type')
        print("in for loop , file type name - ", file_type_name)
        error = validate_file_type(file_type_name)
        if error:
            if "already exists" in error and ignore_existing_file_types:
                continue  # Ignore existing file types if allowed
            errors.append(error)
        else:
            valid_file_types.append(file_type_name.strip())
    
    if errors:
        return {"error": errors}, None
    return None, valid_file_types
