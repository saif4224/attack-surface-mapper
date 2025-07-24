import nmap
from typing import Dict, List

def scan_ports(target: str, top_ports: bool = True) -> Dict:
    """
    Performs an active Nmap scan on the target.
    """
    nm = nmap.PortScanner()
    results = {}
    
    args = '-sV -T4 --open'
    if top_ports:
        args += ' --top-ports 100'
    else:
        args += ' -p 80,443,22,21,3306,5432,8080,8443'
        
    try:
        nm.scan(hosts=target, arguments=args)
        for host in nm.all_hosts():
            results[host] = {'state': nm[host].state(), 'ports': []}
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    port_info = nm[host][proto][port]
                    results[host]['ports'].append({
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', '')
                    })
    except Exception as e:
        results['error'] = str(e)
        
    return results
