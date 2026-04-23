# docker_scanner.py
import docker
import os
import io
import tarfile
import time
import threading
from typing import Dict
from metrics import MetricsCollector  # NOUVEAU


class DockerVirusTotalScanner:
    """Lance les scans VirusTotal dans un conteneur Docker."""

    IMAGE_NAME = "virustotal-sim"

    def __init__(self):
        try:
            self.client = docker.from_env()
            self.connected = True
            print("✓ Connecte au Docker daemon")
        except Exception as e:
            print(f"✗ Erreur Docker: {e}")
            self.connected = False
            self.client = None

        self.container = None
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.startup_time = None  # NOUVEAU
        self.container_start_time = None  # NOUVEAU

        # Suivi interne des scans
        self.scans: list = []
        self._lock = threading.Lock()
        
        # NOUVEAU : Collecteur de métriques
        self.metrics = MetricsCollector('Docker')

    # ------------------------------------------------------------------
    # Helpers prives
    # ------------------------------------------------------------------

    def _make_tar(self, file_path: str) -> io.BytesIO:
        """Cree un stream tar contenant un fichier."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tf:
            tf.add(file_path, arcname=os.path.basename(file_path))
        buf.seek(0)
        return buf

    def _make_script_tar(self, script: str, name: str = "_scan_script.py") -> io.BytesIO:
        """Encode un script Python dans un stream tar."""
        data = script.encode('utf-8')
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tf:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        buf.seek(0)
        return buf

    def _exec(self, cmd: str):
        """Execute une commande."""
        exit_code, output = self.container.exec_run(cmd, stream=False)
        return exit_code, (output or b"")

    # ------------------------------------------------------------------
    # Cycle de vie
    # ------------------------------------------------------------------

    def start_container(self, name: str = "virustotal-scanner") -> bool:
        """Lance le conteneur depuis l'image Dockerfile."""
        if not self.connected:
            return False
        
        startup_start = time.time()  # NOUVEAU
        
        try:
            # Supprime un ancien conteneur du meme nom
            try:
                old = self.client.containers.get(name)
                old.stop()
                old.remove()
            except Exception:
                pass

            # Choisit l'image buildee en priorite
            try:
                self.client.images.get(self.IMAGE_NAME)
                image = self.IMAGE_NAME
                print(f"🐳 Image locale '{image}' utilisee")
            except docker.errors.ImageNotFound:
                image = "python:3.11-slim"
                print(f"⚠️  Image '{self.IMAGE_NAME}' introuvable → fallback '{image}'")

            print(f"🐳 Lancement du conteneur '{name}'...")

            self.container = self.client.containers.run(
                image,
                command="sleep 3600",
                name=name,
                detach=True,
                remove=False,
                environment={
                    'VIRUSTOTAL_API_KEY': self.api_key,
                    'PYTHONUNBUFFERED': '1',
                },
                cpu_quota=50000,
                mem_limit="512m",
            )

            # Fallback : installe requests si image generique
            if image != self.IMAGE_NAME:
                print("📦 Installation des dependances (fallback)...")
                code, out = self._exec("pip install -q requests python-dotenv")
                if code != 0:
                    print(f"⚠️  pip: {out.decode(errors='replace')}")

            self.startup_time = round(time.time() - startup_start, 3)  # NOUVEAU
            self.container_start_time = time.time()  # NOUVEAU
            
            print(f"✓ Conteneur '{name}' pret (ID: {self.container.short_id})")
            print(f"  Temps de démarrage: {self.startup_time}s")  # NOUVEAU
            return True

        except Exception as e:
            print(f"✗ Erreur lancement conteneur: {e}")
            return False

    def cleanup(self):
        """Arrete et supprime le conteneur proprement."""
        if self.container:
            try:
                self.container.stop()
                self.container.remove()
                print("✓ Conteneur arrete et supprime")
            except Exception as e:
                print(f"⚠️  cleanup: {e}")

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def scan_in_container(self, file_path: str) -> Dict:
        """Scanne un fichier dans le conteneur."""
        if not self.container:
            return {'status': 'error', 'message': 'Conteneur non disponible'}

        scan_entry = {
            'file_name': os.path.basename(file_path),
            'status': 'scanning',
            'start_time': time.time(),
            'scan_time': None,
            'detections': None,
        }
        with self._lock:
            self.scans.append(scan_entry)

        try:
            # Copie le fichier cible dans le conteneur
            self.container.put_archive('/tmp', self._make_tar(file_path))

            # Script de scan
            script = f"""
import os, time, random
fp = '/tmp/{os.path.basename(file_path)}'
if os.path.exists(fp):
    size = os.path.getsize(fp)
    t = random.uniform(1.0, 2.5)
    time.sleep(t)
    det = random.randint(0, 3)
    print(f"SCAN_RESULT|SUCCESS|{{size}}|{{det}}|70|{{round(t, 2)}}")
else:
    print("SCAN_RESULT|ERROR|File not found")
"""
            self.container.put_archive('/tmp', self._make_script_tar(script))

            t0 = time.time()
            code, raw = self._exec("python /tmp/_scan_script.py")
            exec_time = time.time() - t0

            line = raw.decode(errors='replace').strip().split('\n')[-1]

            if line.startswith('SCAN_RESULT'):
                parts = line.split('|')
                if len(parts) >= 6 and parts[1] == 'SUCCESS':
                    scan_time = float(parts[5])
                    cpu_usage = self._get_container_cpu()  # NOUVEAU
                    ram_usage = self._get_container_ram()  # NOUVEAU
                    
                    # NOUVEAU : Enregistrer les métriques
                    self.metrics.record_scan(scan_time, cpu_usage, ram_usage)
                    
                    with self._lock:
                        scan_entry['status']     = 'completed'
                        scan_entry['scan_time']  = scan_time
                        scan_entry['detections'] = int(parts[3])
                    return {
                        'status':        'success',
                        'file_name':     os.path.basename(file_path),
                        'file_size':     int(parts[2]),
                        'detections':    int(parts[3]),
                        'engines_total': int(parts[4]),
                        'scan_time':     scan_time,
                        'container_time': round(exec_time, 2),
                    }

            with self._lock:
                scan_entry['status'] = 'error'
            return {
                'status': 'error',
                'message': raw.decode(errors='replace'),
                'container_time': round(exec_time, 2),
            }

        except Exception as e:
            with self._lock:
                scan_entry['status'] = 'error'
            return {'status': 'error', 'message': str(e)}

    # ------------------------------------------------------------------
    # Metriques
    # ------------------------------------------------------------------

    def _get_container_cpu(self) -> float:
        """Retourne l'utilisation CPU du conteneur (%)."""
        if not self.container:
            return 0.0
        try:
            s = self.container.stats(stream=False)
            cpu_d = (s['cpu_stats']['cpu_usage']['total_usage']
                     - s['precpu_stats']['cpu_usage']['total_usage'])
            sys_d = (s['cpu_stats'].get('system_cpu_usage', 0)
                     - s['precpu_stats'].get('system_cpu_usage', 0))
            return round((cpu_d / sys_d) * 100.0 if sys_d > 0 else 0, 2)
        except Exception:
            return 0.0

    def _get_container_ram(self) -> float:
        """Retourne l'utilisation RAM du conteneur (MB)."""
        if not self.container:
            return 0.0
        try:
            s = self.container.stats(stream=False)
            mem_u = s['memory_stats'].get('usage', 0)
            return round(mem_u / 1024 / 1024, 2)
        except Exception:
            return 0.0

    def get_metrics(self) -> Dict:
        """Retourne CPU/RAM + etat des scans."""
        base = {
            'cpu': self._get_container_cpu(),
            'ram': self._get_container_ram(),
            'ram_max': 512.0,
            'ram_pct': 0.0,
            'queued': 0,
            'scanning': 0,
            'completed': 0,
            'scans': [],
            'startup_time': self.startup_time,  # NOUVEAU
            'stats': self.metrics.get_stats(),   # NOUVEAU
        }

        ram_pct = (base['ram'] / base['ram_max']) * 100
        base['ram_pct'] = round(ram_pct, 2)

        with self._lock:
            scans_copy = [dict(s) for s in self.scans]

        base['queued']    = len([s for s in scans_copy if s['status'] == 'queued'])
        base['scanning']  = len([s for s in scans_copy if s['status'] == 'scanning'])
        base['completed'] = len([s for s in scans_copy if s['status'] == 'completed'])
        base['scans']     = scans_copy
        return base