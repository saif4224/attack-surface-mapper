from github import Github
from typing import List, Dict
import time

def search_github_leaks(domain: str, github_token: str) -> List[Dict]:
    """
    Searches GitHub for potentially leaked secrets (API keys, passwords, internal endpoints)
    related to the target domain.
    """
    if not github_token:
        return [{"error": "No GitHub token provided."}]
        
    g = Github(github_token)
    results = []
    
    # Common secret keywords to pair with the domain
    keywords = ['password', 'secret', 'api_key', 'token', 'credentials']
    
    try:
        for keyword in keywords:
            query = f'"{domain}" {keyword} in:file'
            search_results = g.search_code(query=query)
            
            # Limit to top 5 results per keyword to avoid rate limiting for demo
            count = 0
            for item in search_results:
                if count >= 5:
                    break
                results.append({
                    'keyword': keyword,
                    'repository': item.repository.full_name,
                    'file': item.name,
                    'url': item.html_url
                })
                count += 1
            time.sleep(2) # Prevent secondary rate limits
    except Exception as e:
        results.append({'error': str(e)})
        
    return results
