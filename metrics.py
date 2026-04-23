# metrics.py
import time
import threading
from typing import Dict, List
from collections import deque


class MetricsCollector:
    """Collecte et analyse les métriques de performance."""

    def __init__(self, name: str, max_history: int = 60):
        self.name = name
        self.max_history = max_history
        self.lock = threading.Lock()
        
        # Historique des métriques
        self.history = {
            'timestamps': deque(maxlen=max_history),
            'cpu': deque(maxlen=max_history),
            'ram': deque(maxlen=max_history),
            'scan_time': deque(maxlen=max_history),
            'throughput': deque(maxlen=max_history),  # scans/seconde
        }
        
        # Statistiques cumulées
        self.total_scans = 0
        self.total_cpu_usage = 0.0
        self.total_ram_usage = 0.0
        self.startup_time = None
        self.scan_times = []
        self.start_timestamp = None

    def record_scan(self, scan_time: float, cpu: float = 0.0, ram: float = 0.0):
        """Enregistre une métrique de scan."""
        with self.lock:
            current_time = time.time()
            
            if self.start_timestamp is None:
                self.start_timestamp = current_time
                self.startup_time = 0.0
            
            self.history['timestamps'].append(current_time - self.start_timestamp)
            self.history['cpu'].append(cpu)
            self.history['ram'].append(ram)
            self.history['scan_time'].append(scan_time)
            
            self.total_scans += 1
            self.scan_times.append(scan_time)
            self.total_cpu_usage += cpu
            self.total_ram_usage += ram
            
            # Calcul du débit (scans par minute)
            if len(self.history['timestamps']) > 1:
                time_diff = self.history['timestamps'][-1] - self.history['timestamps'][0]
                throughput = (self.total_scans / time_diff * 60) if time_diff > 0 else 0
                self.history['throughput'].append(throughput)

    def get_stats(self) -> Dict:
        """Retourne les statistiques actuelles."""
        with self.lock:
            if not self.scan_times:
                return {
                    'total_scans': 0,
                    'avg_scan_time': 0.0,
                    'min_scan_time': 0.0,
                    'max_scan_time': 0.0,
                    'avg_cpu': 0.0,
                    'avg_ram': 0.0,
                    'throughput': 0.0,
                }
            
            avg_scan_time = sum(self.scan_times) / len(self.scan_times)
            avg_cpu = self.total_cpu_usage / max(len(self.history['cpu']), 1)
            avg_ram = self.total_ram_usage / max(len(self.history['ram']), 1)
            throughput = self.history['throughput'][-1] if self.history['throughput'] else 0.0
            
            return {
                'total_scans': self.total_scans,
                'avg_scan_time': round(avg_scan_time, 3),
                'min_scan_time': round(min(self.scan_times), 3),
                'max_scan_time': round(max(self.scan_times), 3),
                'avg_cpu': round(avg_cpu, 2),
                'avg_ram': round(avg_ram, 2),
                'throughput': round(throughput, 2),
            }

    def get_history(self) -> Dict:
        """Retourne l'historique des métriques."""
        with self.lock:
            return {
                'timestamps': list(self.history['timestamps']),
                'cpu': list(self.history['cpu']),
                'ram': list(self.history['ram']),
                'scan_time': list(self.history['scan_time']),
                'throughput': list(self.history['throughput']),
            }