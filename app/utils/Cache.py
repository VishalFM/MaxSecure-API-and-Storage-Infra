import hashlib


def generate_md5_from_url(url):
    """
    Generate an MD5 hash for a given URL.
    
    Args:
        url (str): The input URL.
        
    Returns:
        str: The MD5 hash of the normalized URL.
    """
    if not url:
        raise ValueError("URL cannot be empty")
    
    normalized_url = url.strip().lower()
    md5_hash = hashlib.md5(normalized_url.encode('utf-8')).hexdigest()
    return md5_hash