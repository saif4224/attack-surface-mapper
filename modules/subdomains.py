import requests
import re
from typing import List

def get_subdomains(domain: str) -> List[str]:
    """
    Fetches subdomains for a given domain using crt.sh (Certificate Transparency Logs).
    This is a passive technique.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    # Clean up wildcard domains and newlines
                    clean_names = name.split('\n')
                    for cn in clean_names:
                        cn = cn.strip().replace('*.', '')
                        if cn.endswith(domain):
                            subdomains.add(cn)
    except Exception as e:
        pass # Silently fail or log in a real app, returning what we have so far
        
    return sorted(list(subdomains))
