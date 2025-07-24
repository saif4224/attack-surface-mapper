import argparse
import os
import concurrent.futures
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Recon Modules
from modules.subdomains import get_subdomains
from modules.ports import scan_ports
from modules.shodan_lookup import shodan_scan
from modules.github_leaks import search_github_leaks
from modules.cloud_storage import check_s3_buckets
from modules.wayback import get_wayback_urls
from modules.waf_detector import detect_waf
from modules.report import generate_report

console = Console()

def print_banner():
    banner = """
    █████╗ ███████╗ ██████╗ ██╗███████╗
    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
    ███████║█████╗  ██║  ███╗██║███████╗
    ██╔══██║██╔══╝  ██║   ██║██║╚════██║
    ██║  ██║███████╗╚██████╔╝██║███████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
    Attack Surface Mapper & OSINT Engine v2.0
    """
    console.print(Panel(banner, style="bold blue"))

def main():
    parser = argparse.ArgumentParser(description="Aegis-OSINT: Automated Attack Surface Mapping")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("--shodan", help="Shodan API Key (or set SHODAN_API_KEY env var)")
    parser.add_argument("--github", help="GitHub Token (or set GITHUB_TOKEN env var)")
    parser.add_argument("-o", "--output", default="report.json", help="Output JSON file")
    
    args = parser.parse_args()
    target = args.domain
    shodan_key = args.shodan or os.environ.get("SHODAN_API_KEY")
    github_token = args.github or os.environ.get("GITHUB_TOKEN")
    
    print_banner()
    console.print(f"[bold green][+][/bold green] Initiating Attack Surface Mapping for: [bold white]{target}[/bold white]\n")
    
    aggregated_data = {
        "target": target, 
        "waf_status": {},
        "subdomains": [], 
        "ports": {}, 
        "shodan": {}, 
        "github_leaks": [],
        "cloud_storage": [],
        "wayback_urls": []
    }
    
    # Execute Pre-Requisite Checks (WAF & Subdomains)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        t_waf = progress.add_task("[cyan]Fingerprinting Web Application Firewalls (WAF)...", total=None)
        aggregated_data["waf_status"] = detect_waf(target)
        progress.update(t_waf, completed=True)
        
        t_sub = progress.add_task("[cyan]Enumerating subdomains via crt.sh (Passive)...", total=None)
        subdomains = get_subdomains(target)
        aggregated_data["subdomains"] = subdomains
        progress.update(t_sub, completed=True)
        
    console.print(f"[bold green][+][/bold green] WAF Status: [bold yellow]{aggregated_data['waf_status'].get('provider', 'None Detected')}[/bold yellow]")
    console.print(f"[bold green][+][/bold green] Discovered [bold white]{len(subdomains)}[/bold white] subdomains.")

    scan_target = subdomains[0] if subdomains else target

    # Multithreaded Execution for Heavy Modules
    console.print(f"[bold green][+][/bold green] Launching Asynchronous Scanning Engine (Threads: 5)...")
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_scan = progress.add_task(f"[cyan]Active port scan on {scan_target}...", total=None)
        task_s3 = progress.add_task("[cyan]Brute-forcing Cloud Storage (AWS S3)...", total=None)
        task_wayback = progress.add_task("[cyan]Mining Wayback Machine for hidden endpoints...", total=None)
        task_shodan = progress.add_task("[cyan]Querying Shodan for historical vulnerabilities...", total=None) if shodan_key else None
        task_github = progress.add_task("[cyan]Hunting for leaked secrets on GitHub...", total=None) if github_token else None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Submit tasks
            f_ports = executor.submit(scan_ports, scan_target, False)
            f_s3 = executor.submit(check_s3_buckets, target)
            f_wayback = executor.submit(get_wayback_urls, target)
            f_shodan = executor.submit(shodan_scan, target, shodan_key) if shodan_key else None
            f_github = executor.submit(search_github_leaks, target, github_token) if github_token else None
            
            # Retrieve results
            aggregated_data["ports"] = f_ports.result()
            progress.update(task_scan, completed=True)
            console.print(f"  [green]➔[/green] Active port scan complete.")
            
            aggregated_data["cloud_storage"] = f_s3.result()
            progress.update(task_s3, completed=True)
            console.print(f"  [green]➔[/green] Cloud storage check complete. Checked AWS S3 permutations.")
            
            aggregated_data["wayback_urls"] = f_wayback.result()
            progress.update(task_wayback, completed=True)
            console.print(f"  [green]➔[/green] Wayback Machine mining complete. Found [bold white]{len(aggregated_data['wayback_urls'])}[/bold white] endpoints.")
            
            if f_shodan:
                shodan_res = f_shodan.result()
                aggregated_data["shodan"] = shodan_res
                progress.update(task_shodan, completed=True)
                console.print(f"  [green]➔[/green] Shodan lookup complete.")
                
            if f_github:
                github_res = f_github.result()
                aggregated_data["github_leaks"] = github_res
                progress.update(task_github, completed=True)
                console.print(f"  [green]➔[/green] GitHub scraping complete.")

    # Reporting
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_report = progress.add_task("[cyan]Aggregating telemetry and generating JSON report...", total=None)
        report_file = generate_report(aggregated_data, args.output)
        progress.update(task_report, completed=True)
        
    console.print(f"\n[bold green][✓][/bold green] Attack Surface Mapping Complete!")
    console.print(f"Report saved to: [bold white]{report_file}[/bold white]")

if __name__ == "__main__":
    main()
