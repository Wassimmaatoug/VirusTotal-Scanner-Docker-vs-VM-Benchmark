# vm_scanner.py
import time
import random
import threading
from typing import Dict
from metrics import MetricsCollector  


class VMVirusTotalScanner:
    

    def __init__(self, name: str = 'VM'):
        self.name = name
        self.scans = []
        self.processing = False
        self._lock = threading.Lock()
        self.startup_time = None  
        self.metrics = MetricsCollector('VM')  

    def add_scan(self, file_name: str, file_size: int = 1024) -> Dict:
        """Ajoute un scan a la queue et retourne l'entree cree."""
        scan = {
            'id':         f"vm_{len(self.scans)}_{int(time.time()*1000)}",
            'file_name':  file_name,
            'file_size':  file_size,
            'status':     'queued',
            'progress':   0,
            'start_time': None,
            'result':     None,
        }
        with self._lock:
            self.scans.append(scan)
        return scan

    def process_scans(self):
        """Traite les scans sequentiellement dans un thread daemon."""
        self.processing = True
        startup_start = time.time()  # NOUVEAU

        def _process():
            startup_measured = False  # NOUVEAU
            
            while self.processing:
                with self._lock:
                    scan = next((s for s in self.scans if s['status'] == 'queued'), None)

                if not scan:
                    time.sleep(0.2)
                    continue

                
                if not startup_measured:
                    self.startup_time = round(time.time() - startup_start, 3)
                    startup_measured = True

                scan['status']     = 'scanning'
                scan['start_time'] = time.time()

                
                scan_duration = random.uniform(3.0, 5.0)
                cpu_usage = random.uniform(15.0, 45.0)  # NOUVEAU
                ram_usage = random.uniform(100.0, 250.0)  # NOUVEAU
                steps = 20

                for step in range(steps):
                    with self._lock:
                        scan['progress'] = int((step / steps) * 100)
                    time.sleep(scan_duration / steps)

                with self._lock:
                    scan['progress'] = 100
                    scan['status']   = 'completed'
                    scan['result']   = {
                        'detections':    random.randint(0, 2),
                        'engines_total': 70,
                        'scan_time':     round(time.time() - scan['start_time'], 2),
                    }
                
                
                self.metrics.record_scan(
                    scan['result']['scan_time'],
                    cpu_usage,
                    ram_usage
                )

        threading.Thread(target=_process, daemon=True).start()

    def get_status(self) -> Dict:
        """Retourne l'etat actuel de la queue."""
        with self._lock:
            return {
                'queued':    len([s for s in self.scans if s['status'] == 'queued']),
                'scanning':  len([s for s in self.scans if s['status'] == 'scanning']),
                'completed': len([s for s in self.scans if s['status'] == 'completed']),
                'scans':     [dict(s) for s in self.scans],
                'startup_time': self.startup_time,  
                'stats': self.metrics.get_stats(),   
            }

    def stop(self):
        """Arrete le traitement."""
        self.processing = False