import hashlib
from urllib.parse import urlparse
import tldextract

def get_md5_from_url(url):
    if not url:
        raise ValueError("URL cannot be empty")
    
    normalized_url = url.strip().lower()
    md5_hash = hashlib.md5(normalized_url.encode('utf-8')).hexdigest()
    return md5_hash

def extract_main_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain

def get_main_domain(url):
    extracted = tldextract.extract(url)
    main_domain = f"{extracted.domain}.{extracted.suffix}"
    return main_domain
