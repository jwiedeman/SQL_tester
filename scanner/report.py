import csv
from typing import List, Dict


class CSVReporter:
    def __init__(self, filename: str):
        self.filename = filename
        self.rows: List[Dict[str, str]] = []

    def add_result(self, url: str, param: str, payload: str, method: str, vulnerable: bool):
        self.rows.append({
            'url': url,
            'parameter': param,
            'payload': payload,
            'method': method,
            'vulnerable': 'Y' if vulnerable else 'N',
        })

    def write(self):
        fieldnames = ['url', 'parameter', 'payload', 'method', 'vulnerable']
        with open(self.filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.rows)
