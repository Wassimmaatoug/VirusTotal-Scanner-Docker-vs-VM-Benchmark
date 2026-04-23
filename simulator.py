# simulator.py
import time
import random
import threading
from typing import Dict


class VirusTotalSimulator:
    """Simule un scanner VirusTotal avec resultats realistes."""

    # CORRECTION : les valeurs random doivent etre calculees au moment du scan,
    # pas a la definition de la classe (sinon toutes les instances partagent
    # les memes valeurs figees).
    THREAT_PROFILES = {
        'clean':      {'detection_rate': 0,  'scan_time_min': 0.8, 'scan_time_max': 1.5, 'engines_scanned': 70},
        'suspicious': {'detection_rate': None, 'det_min': 1,  'det_max': 5,  'scan_time_min': 1.2, 'scan_time_max': 2.0, 'engines_scanned': 70},
        'malicious':  {'detection_rate': None, 'det_min': 10, 'det_max': 50, 'scan_time_min': 1.5, 'scan_time_max': 3.0, 'engines_scanned': 70},
    }

    def __init__(self, name: str = 'Simulator'):
        self.name = name
        self.scanning = False
        self.scan_queue = []
        self.results = {}
        self._lock = threading.Lock()

    def add_scan(self, file_name: str, threat_type: str = 'clean') -> str:
        """Ajoute un fichier a scanner."""
        scan_id = f"{self.name}_{len(self.scan_queue)}_{int(time.time()*1000)}"

        with self._lock:
            self.scan_queue.append({
                'id':         scan_id,
                'file_name':  file_name,
                'threat_type': threat_type,
                'status':     'queued',
                'progress':   0,
                'start_time': None,
                'end_time':   None,
            })

        return scan_id

    def process_scans(self):
        """Lance le traitement des scans dans un thread daemon."""
        self.scanning = True

        def _process():
            while self.scanning:
                with self._lock:
                    scan = next((s for s in self.scan_queue if s['status'] == 'queued'), None)

                if not scan:
                    time.sleep(0.1)
                    continue

                scan['status']     = 'scanning'
                scan['start_time'] = time.time()

                profile = self.THREAT_PROFILES[scan['threat_type']]

                # CORRECTION : calcul des valeurs aleatoires au moment du scan
                scan_duration = random.uniform(profile['scan_time_min'], profile['scan_time_max'])
                if profile['detection_rate'] is not None:
                    detection_rate = profile['detection_rate']
                else:
                    detection_rate = random.randint(profile['det_min'], profile['det_max'])

                steps = max(1, int(scan_duration * 10))
                for step in range(steps):
                    with self._lock:
                        scan['progress'] = int((step / steps) * 100)
                    time.sleep(scan_duration / steps)

                with self._lock:
                    scan['progress']       = 100
                    scan['status']         = 'completed'
                    scan['end_time']       = time.time()
                    scan['detection_rate'] = detection_rate
                    scan['engines_total']  = profile['engines_scanned']
                    self.results[scan['id']] = {
                        'file_name':      scan['file_name'],
                        'threat_type':    scan['threat_type'],
                        'detection_rate': detection_rate,
                        'engines_total':  profile['engines_scanned'],
                        'scan_time':      round(scan['end_time'] - scan['start_time'], 2),
                    }

        threading.Thread(target=_process, daemon=True).start()

    def get_queue_status(self) -> Dict:
        """Etat actuel de la queue."""
        with self._lock:
            return {
                'queued':    len([s for s in self.scan_queue if s['status'] == 'queued']),
                'scanning':  len([s for s in self.scan_queue if s['status'] == 'scanning']),
                'completed': len([s for s in self.scan_queue if s['status'] == 'completed']),
                'total':     len(self.scan_queue),
                'scans':     [dict(s) for s in self.scan_queue],
            }

    def stop(self):
        """Arrete le traitement."""
        self.scanning = False
