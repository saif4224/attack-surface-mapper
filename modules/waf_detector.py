import requests
from typing import Dict

def detect_waf(domain: str) -> Dict[str, str]:
    """
    Analyzes HTTP response headers to identify Web Application Firewalls (WAF).
    """
    target_url = f"https://{domain}" if not domain.startswith("http") else domain
    
    # Common WAF signatures in headers
    waf_signatures = {
        "Cloudflare": {"server": "cloudflare", "cf-ray": ""},
        "AWS WAF": {"server": "awselb", "x-amz-cf-id": ""},
        "Akamai": {"server": "akamai", "x-akamai-transformed": ""},
        "Sucuri": {"server": "sucuri", "x-sucuri-id": ""},
        "Imperva": {"server": "imperva", "x-iinfo": ""}
    }
    
    result = {"status": "No WAF Detected", "provider": None}
    
    try:
        # Use a realistic User-Agent
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(target_url, headers=headers, timeout=10)
        
        resp_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        # Check against signatures
        for waf_name, sigs in waf_signatures.items():
            for sig_key, sig_val in sigs.items():
                if sig_key in resp_headers:
                    if sig_val == "" or sig_val in resp_headers[sig_key]:
                        result = {"status": "WAF Detected", "provider": waf_name}
                        return result
                        
    except Exception as e:
        result = {"status": "Error", "provider": str(e)}
        
    return result
