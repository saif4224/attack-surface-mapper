import requests
from typing import List, Dict

def check_s3_buckets(domain: str) -> List[Dict]:
    """
    Brute-forces common AWS S3 bucket naming conventions to find exposed data.
    """
    # Extract base name from domain (e.g. example.com -> example)
    base_name = domain.split('.')[0] if '.' in domain else domain
    
    # Common bucket suffixes used by dev teams
    suffixes = ['-dev', '-prod', '-staging', '-backup', '-assets', '-media', '-public']
    permutations = [base_name] + [f"{base_name}{suffix}" for suffix in suffixes]
    
    discovered_buckets = []
    
    # Check each permutation
    for bucket in permutations:
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            # We don't want to actually download big files, just check the header/status
            response = requests.head(url, timeout=5)
            
            # 403 means it exists but is private (still good intel)
            # 200 means it exists and is public (critical finding)
            if response.status_code == 200:
                discovered_buckets.append({"bucket": url, "status": "Public/Exposed"})
            elif response.status_code == 403:
                discovered_buckets.append({"bucket": url, "status": "Private (Exists)"})
        except requests.exceptions.RequestException:
            pass # Ignore timeouts or connection errors (bucket probably doesn't exist)
            
    return discovered_buckets
