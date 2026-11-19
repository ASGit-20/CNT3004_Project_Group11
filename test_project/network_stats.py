"""
CNT3004 - Network Performance Statistics

This file is designed to keep metrics in memory while the server runs
and save them to CSV files when the server shuts down.
"""


import csv
import threading
import time
from pathlib import Path



class NetworkStats:
    def __init__(self, output_directory="network_logs"):
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.transfer_records = []
        self.response_records = []

        # Multiple client threads may record statistics simultaneously.
        self.lock = threading.Lock()

    def record_transfer(
        self,
        direction,
        username,
        filename,
        bytes_transferred,
        duration_seconds
    ):
        """Record an upload or download and calculate its average data rate."""

        if duration_seconds > 0:
            data_rate = (
                bytes_transferred / (1024 * 1024)
            ) / duration_seconds
        else:
            data_rate = 0.0

        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "direction": direction,
            "username": username,
            "filename": filename,
            "bytes_transferred": bytes_transferred,
            "transfer_time_seconds": round(duration_seconds, 6),
            "data_rate_MB_per_second": round(data_rate, 6)
        }

        with self.lock:
            self.transfer_records.append(record)

        print(
            f"[STATS] {direction.upper()} {filename}: "
            f"{bytes_transferred} bytes in {duration_seconds:.3f}s "
            f"({data_rate:.3f} MB/s)"
        )

    def record_response(self, username, command, response_time_seconds):
        """Record the time taken by the server to handle one client command."""

        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "command": command,
            "response_time_seconds": round(response_time_seconds, 6)
        }

        with self.lock:
            self.response_records.append(record)

    def save(self):
        """Write collected metrics to CSV files for offline analysis."""

        with self.lock:
            transfer_copy = list(self.transfer_records)
            response_copy = list(self.response_records)

        transfer_file = self.output_directory / "transfer_stats.csv"
        response_file = self.output_directory / "response_stats.csv"

        # Always create both CSV files, even if they contain no records.
        with transfer_file.open("w", newline="", encoding="utf-8") as file:
            fieldnames = [
                "timestamp",
                "direction",
                "username",
                "filename",
                "bytes_transferred",
                "transfer_time_seconds",
                "data_rate_MB_per_second"
            ]

            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(transfer_copy)

        with response_file.open("w", newline="", encoding="utf-8") as file:
            fieldnames = [
                "timestamp",
                "username",
                "command",
                "response_time_seconds"
            ]

            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(response_copy)

        print(f"[ANALYSIS] Transfer statistics saved: {transfer_file.resolve()}")
        print(f"[ANALYSIS] Response statistics saved: {response_file.resolve()}")