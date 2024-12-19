import hashlib
from urllib.parse import urlparse
import tldextract

def get_md5_from_url(url):
    return hashlib.md5(url.strip().lower().encode('utf-8')).hexdigest()

def extract_main_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain

def get_main_domain(url):
    extracted = tldextract.extract(url)
    main_domain = f"{extracted.domain}.{extracted.suffix}"
    return main_domain
