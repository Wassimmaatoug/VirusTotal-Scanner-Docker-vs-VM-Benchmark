# virustotal_scanner.py
import requests
import os
import time
import hashlib
from typing import Dict
from dotenv import load_dotenv

load_dotenv()


class VirusTotalScanner:
    """Client VirusTotal API v3."""

    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.api_url = os.getenv('VIRUSTOTAL_API_URL', 'https://www.virustotal.com/api/v3')

        # CORRECTION : verifier que la cle est presente et non vide
        if not self.api_key:
            raise ValueError(
                "VIRUSTOTAL_API_KEY manquant. "
                "Definissez-le dans votre fichier .env."
            )

        self.headers     = {'x-apikey': self.api_key}
        self.rate_limit  = 4        # requetes/min (plan gratuit)
        self.last_request = 0.0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _rate_limit_wait(self):
        """Respecte le rate limit de l'API gratuite (4 req/min)."""
        min_interval = 60.0 / self.rate_limit
        elapsed = time.time() - self.last_request
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self.last_request = time.time()

    # ------------------------------------------------------------------
    # Scan de fichier
    # ------------------------------------------------------------------

    def scan_file(self, file_path: str) -> Dict:
        """
        Soumet un fichier a VirusTotal et retourne l'identifiant d'analyse.

        Retourne:
            {
                'status'      : 'queued' | 'error',
                'analysis_id' : str,
                'file_name'   : str,
                'file_size'   : int,
                'scan_time'   : float,
                'message'     : str,
            }
        """
        if not os.path.exists(file_path):
            return {
                'status':    'error',
                'message':   f'Fichier non trouve: {file_path}',
                'scan_time': 0,
            }

        t0 = time.time()
        try:
            self._rate_limit_wait()

            with open(file_path, 'rb') as f:
                resp = requests.post(
                    f'{self.api_url}/files',
                    headers=self.headers,
                    files={'file': (os.path.basename(file_path), f)},
                    timeout=30,
                )

            scan_time = round(time.time() - t0, 2)

            if resp.status_code == 200:
                data = resp.json()
                return {
                    'status':      'queued',
                    'analysis_id': data['data']['id'],
                    'file_name':   os.path.basename(file_path),
                    'file_size':   os.path.getsize(file_path),
                    'scan_time':   scan_time,
                    'message':     'Scan soumis avec succes',
                }

            if resp.status_code == 429:
                return {
                    'status':    'error',
                    'message':   'Rate limit depasse (plan gratuit : 4 req/min)',
                    'scan_time': scan_time,
                }

            return {
                'status':    'error',
                'message':   f'HTTP {resp.status_code}: {resp.text}',
                'scan_time': scan_time,
            }

        except requests.exceptions.Timeout:
            return {'status': 'error', 'message': 'Timeout', 'scan_time': round(time.time()-t0, 2)}
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'scan_time': round(time.time()-t0, 2)}

    # ------------------------------------------------------------------
    # Recuperation des resultats
    # ------------------------------------------------------------------

    def get_analysis(self, analysis_id: str) -> Dict:
        """Interroge l'API pour recuperer le resultat d'une analyse."""
        try:
            self._rate_limit_wait()

            resp = requests.get(
                f'{self.api_url}/analyses/{analysis_id}',
                headers=self.headers,
                timeout=30,
            )

            if resp.status_code == 200:
                data  = resp.json()
                attrs = data['data']['attributes']
                stats = attrs.get('stats', {})
                total = sum(stats.values())
                return {
                    'status':         'success',
                    'analysis_id':    analysis_id,
                    'state':          attrs.get('status', 'unknown'),
                    'detections':     stats.get('malicious', 0),
                    'engines_total':  total,
                    'detection_rate': f"{stats.get('malicious', 0)}/{total}",
                }

            # Analyse encore en cours
            return {
                'status':      'pending',
                'analysis_id': analysis_id,
                'message':     'Analyse en cours',
            }

        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # ------------------------------------------------------------------
    # Scan par hash (plus rapide, pas de soumission)
    # ------------------------------------------------------------------

    def scan_hash(self, file_hash: str) -> Dict:
        """Verifie un fichier par son hash SHA-256 (sans le soumettre)."""
        try:
            self._rate_limit_wait()

            resp = requests.get(
                f'{self.api_url}/files/{file_hash}',
                headers=self.headers,
                timeout=10,
            )

            if resp.status_code == 200:
                data  = resp.json()
                stats = data['data']['attributes'].get('last_analysis_stats', {})
                total = sum(stats.values())
                return {
                    'status':         'success',
                    'hash':           file_hash,
                    'detections':     stats.get('malicious', 0),
                    'engines_total':  total,
                    'detection_rate': f"{stats.get('malicious', 0)}/{total}",
                }

            return {
                'status':  'not_found',
                'hash':    file_hash,
                'message': 'Hash inconnu de VirusTotal',
            }

        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # ------------------------------------------------------------------
    # Utilitaire
    # ------------------------------------------------------------------

    @staticmethod
    def get_file_hash(file_path: str, algo: str = 'sha256') -> str:
        """Calcule le hash d'un fichier par blocs (fichiers volumineux supportes)."""
        hasher = hashlib.new(algo)
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
