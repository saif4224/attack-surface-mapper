import matplotlib.pyplot as plt
import os
import numpy as np

os.makedirs("assets", exist_ok=True)

# 1. Port Distribution (Bar Chart)
plt.figure(figsize=(8, 5))
ports = ['443 (HTTPS)', '80 (HTTP)', '22 (SSH)', '8080 (Proxy)', '3306 (MySQL)', '8443 (HTTPS)']
counts = [142, 115, 45, 23, 8, 12]
colors = ['#2ecc71', '#3498db', '#e74c3c', '#f1c40f', '#9b59b6', '#34495e']
plt.bar(ports, counts, color=colors)
plt.title("Discovered Services Port Distribution", fontsize=14)
plt.ylabel("Number of Hosts", fontsize=12)
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("assets/port_distribution.png", format="PNG", dpi=150)
plt.close()

# 2. Leaked Secrets Breakdown (Donut Chart)
plt.figure(figsize=(7, 7))
labels = ['AWS API Keys', 'Database Passwords', 'OAuth Tokens', 'Private SSH Keys']
sizes = [45, 25, 20, 10]
colors = ['#ff9999','#66b3ff','#99ff99','#ffcc99']
plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90, pctdistance=0.85, explode=(0.05, 0.05, 0.05, 0.05))
centre_circle = plt.Circle((0,0),0.70,fc='white')
fig = plt.gcf()
fig.gca().add_artist(centre_circle)
plt.title("GitHub Leaked Secrets Breakdown", fontsize=14)
plt.tight_layout()
plt.savefig("assets/leaked_secrets.png", format="PNG", dpi=150)
plt.close()

# 3. Cloud Asset Exposure (Horizontal Bar)
plt.figure(figsize=(9, 4))
assets = ['S3 Buckets (Exposed)', 'S3 Buckets (Private)', 'Azure Blobs', 'GCP Storage']
counts = [12, 85, 4, 7]
y_pos = np.arange(len(assets))
plt.barh(y_pos, counts, color=['#e74c3c', '#2ecc71', '#3498db', '#f1c40f'])
plt.yticks(y_pos, assets)
plt.xlabel("Number of Assets Discovered")
plt.title("Cloud Storage Exposure Matrix", fontsize=14)
plt.tight_layout()
plt.savefig("assets/cloud_exposure.png", format="PNG", dpi=150)
plt.close()

# 4. Vulnerability Severity (Stacked Area/Bar)
plt.figure(figsize=(8, 5))
severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
counts = [2, 14, 45, 112, 340]
plt.bar(severities, counts, color=['#c0392b', '#e67e22', '#f1c40f', '#3498db', '#bdc3c7'])
plt.title("CVE Severity Distribution (Shodan Intelligence)", fontsize=14)
plt.ylabel("Number of Vulnerabilities")
plt.tight_layout()
plt.savefig("assets/cve_severity.png", format="PNG", dpi=150)
plt.close()

print("All charts generated successfully.")
