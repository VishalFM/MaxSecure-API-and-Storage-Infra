import hashlib
from urllib.parse import urlparse
import tldextract


def get_md5_from_url(url):
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

def extract_main_domain(url):
    """
    Extract the main domain from a URL.
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain

def get_main_domain(url):
    # Extract domain components
    extracted = tldextract.extract(url)
    # Combine the domain and suffix to form the main domain
    main_domain = f"{extracted.domain}.{extracted.suffix}"
    return main_domain