import requests
import json
from typing import List

def get_wayback_urls(domain: str) -> List[str]:
    """
    Queries the Wayback Machine CDX API for historical URLs and orphaned endpoints.
    """
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    
    discovered_urls = set()
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            # The first item is usually the header ['original']
            if len(data) > 1:
                for entry in data[1:]:
                    if len(entry) > 0:
                        endpoint = entry[0]
                        # Filter out common junk to keep the report clean
                        if not any(endpoint.endswith(ext) for ext in ['.png', '.jpg', '.css', '.woff', '.gif']):
                            discovered_urls.add(endpoint)
                            
                # For demo speed, limit to top 20 interesting endpoints
                return sorted(list(discovered_urls))[:20]
    except Exception:
        pass
        
    return list(discovered_urls)
