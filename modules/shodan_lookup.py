import shodan
from typing import Dict

def shodan_scan(ip_or_domain: str, api_key: str) -> Dict:
    """
    Passively looks up historical vulnerabilities and open ports for a target using Shodan.
    """
    if not api_key:
        return {"error": "No Shodan API key provided."}
        
    api = shodan.Shodan(api_key)
    results = {}
    
    try:
        host = api.host(ip_or_domain)
        results['ip'] = host.get('ip_str')
        results['org'] = host.get('org', 'n/a')
        results['os'] = host.get('os', 'n/a')
        results['ports'] = host.get('ports', [])
        results['vulns'] = host.get('vulns', [])
    except shodan.APIError as e:
        results['error'] = str(e)
        
    return results
