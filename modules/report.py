import json
import os
from datetime import datetime

def generate_report(data: dict, output_file: str):
    """
    Saves the aggregated ASM data into a structured JSON report.
    """
    report = {
        "metadata": {
            "target": data.get("target"),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tool": "Aegis-OSINT Attack Surface Mapper"
        },
        "findings": data
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=4)
        
    return output_file
