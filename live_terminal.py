# live_terminal.py
import time
import os
import threading
import tempfile
from dotenv import load_dotenv

load_dotenv()

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich import box
except ImportError:
    raise ImportError("Installez 'rich' : pip install rich")

from docker_scanner import DockerVirusTotalScanner
from vm_scanner import VMVirusTotalScanner
from simulator import VirusTotalSimulator

console = Console()

# --------------------------------------------------------------------------
# Instances
# --------------------------------------------------------------------------
docker_scanner = None
vm_scanner = VMVirusTotalScanner('VM')
simulator  = VirusTotalSimulator('Simulator')


# --------------------------------------------------------------------------
# Construction de l'affichage Rich
# --------------------------------------------------------------------------
def _bar(value: int, total: int, width: int = 20, color: str = 'green') -> str:
    """Barre de progression ASCII coloree."""
    if total == 0:
        pct = 0
    else:
        pct = min(value / total, 1.0)
    filled = int(pct * width)
    bar = '█' * filled + '░' * (width - filled)
    return f"[{color}]{bar}[/{color}] {int(pct*100):3d}%"


def build_layout(elapsed: float) -> Panel:
    """Construit le rendu Rich pour l'instant t."""

    docker_status = docker_scanner.get_metrics() if docker_scanner else {
        'cpu': 0, 'ram': 0, 'queued': 0, 'scanning': 0, 'completed': 0, 
        'scans': [], 'stats': {}
    }
    vm_status  = vm_scanner.get_status()
    sim_status = simulator.get_queue_status()

    total_files = 5

    # --- Tableau Docker ---
    docker_stats = docker_status.get('stats', {})
    t_docker = Table(title="[bold cyan]🐳 Docker Scanner[/bold cyan]",
                     box=box.ROUNDED, border_style='cyan', expand=True)
    t_docker.add_column("Metrique", style='bold cyan')
    t_docker.add_column("Valeur", style='cyan')
    t_docker.add_row("Completes",     str(docker_status.get('completed', 0)))
    t_docker.add_row("En scan",       str(docker_status.get('scanning', 0)))
    t_docker.add_row("CPU",           f"{docker_status.get('cpu', 0):.1f}%")
    t_docker.add_row("RAM",           f"{docker_status.get('ram', 0):.0f}MB")
    t_docker.add_row("Démarrage",     f"{docker_status.get('startup_time', 0):.2f}s")
    t_docker.add_row("Temps moyen",   f"{docker_stats.get('avg_scan_time', 0):.3f}s")
    t_docker.add_row("Débit",         f"{docker_stats.get('throughput', 0):.1f}/min")
    t_docker.add_row("Progres",       _bar(docker_status.get('completed', 0), total_files, color='cyan'))

    # --- Tableau VM ---
    vm_scans_done = vm_status['completed']
    vm_stats = vm_status.get('stats', {})
    vm_times = [s['result']['scan_time'] for s in vm_status['scans']
                if s['status'] == 'completed' and s.get('result')]
    vm_avg = sum(vm_times) / len(vm_times) if vm_times else 0.0

    t_vm = Table(title="[bold yellow]⚙️  VM Scanner[/bold yellow]",
                 box=box.ROUNDED, border_style='yellow', expand=True)
    t_vm.add_column("Metrique", style='bold yellow')
    t_vm.add_column("Valeur", style='yellow')
    t_vm.add_row("Completes",      str(vm_scans_done))
    t_vm.add_row("En scan",        str(vm_status['scanning']))
    t_vm.add_row("CPU moyen",      f"{vm_stats.get('avg_cpu', 0):.1f}%")
    t_vm.add_row("RAM moyen",      f"{vm_stats.get('avg_ram', 0):.0f}MB")
    t_vm.add_row("Démarrage",      f"{vm_status.get('startup_time', 0):.2f}s")
    t_vm.add_row("Temps moyen",    f"{vm_stats.get('avg_scan_time', 0):.3f}s")
    t_vm.add_row("Débit",          f"{vm_stats.get('throughput', 0):.1f}/min")
    t_vm.add_row("Progres",        _bar(vm_scans_done, total_files, color='yellow'))

    # --- Tableau Simulateur ---
    t_sim = Table(title="[bold green]🤖 Simulator[/bold green]",
                  box=box.ROUNDED, border_style='green', expand=True)
    t_sim.add_column("Metrique", style='bold green')
    t_sim.add_column("Valeur", style='green')
    t_sim.add_row("Completes", str(sim_status['completed']))
    t_sim.add_row("En scan",   str(sim_status['scanning']))
    t_sim.add_row("En file",   str(sim_status['queued']))
    t_sim.add_row("Progres",   _bar(sim_status['completed'], total_files, color='green'))

    cols = Columns([t_docker, t_vm, t_sim], expand=True)

    # --- Tableau de comparaison ---
    t_comparison = Table(title="[bold magenta]📊 Comparaison[/bold magenta]",
                        box=box.ROUNDED, border_style='magenta', expand=True)
    t_comparison.add_column("Metrique", style='bold magenta')
    t_comparison.add_column("Docker", style='cyan')
    t_comparison.add_column("VM", style='yellow')
    
    docker_completed = docker_status.get('completed', 0)
    docker_avg = docker_stats.get('avg_scan_time', 0)
    docker_throughput = docker_stats.get('throughput', 0)
    
    vm_throughput = vm_stats.get('throughput', 0)
    
    t_comparison.add_row("Scans", str(docker_completed), str(vm_scans_done))
    t_comparison.add_row("Temps moyen", f"{docker_avg:.3f}s", f"{vm_avg:.3f}s")
    t_comparison.add_row("Démarrage", f"{docker_status.get('startup_time', 0):.2f}s", 
                        f"{vm_status.get('startup_time', 0):.2f}s")
    t_comparison.add_row("Débit", f"{docker_throughput:.1f}/min", f"{vm_throughput:.1f}/min")
    t_comparison.add_row("CPU moyen", f"{docker_stats.get('avg_cpu', 0):.1f}%", 
                        f"{vm_stats.get('avg_cpu', 0):.1f}%")
    t_comparison.add_row("RAM moyen", f"{docker_stats.get('avg_ram', 0):.0f}MB", 
                        f"{vm_stats.get('avg_ram', 0):.0f}MB")

    # --- Tableau de scans en cours ---
    t_scans = Table(title="[bold white]🔍 Scans en cours[/bold white]",
                    box=box.SIMPLE_HEAD, expand=True)
    t_scans.add_column("Scanner", style='bold')
    t_scans.add_column("Fichier")
    t_scans.add_column("Statut")

    for s in docker_status.get('scans', []):
        status_color = {'scanning': 'cyan', 'completed': 'green', 'error': 'red'}.get(s['status'], 'white')
        t_scans.add_row(
            '[cyan]Docker[/cyan]',
            s.get('file_name', '?'),
            f"[{status_color}]{s['status']}[/{status_color}]",
        )

    for s in vm_status['scans']:
        status_color = {'scanning': 'yellow', 'completed': 'green', 'error': 'red'}.get(s['status'], 'white')
        t_scans.add_row(
            '[yellow]VM[/yellow]',
            s.get('file_name', '?'),
            f"[{status_color}]{s['status']}[/{status_color}]",
        )

    title = Text(f"VirusTotal Scanner — Docker vs VM  |  t={elapsed:.1f}s", style="bold green")

    from rich.layout import Layout
    layout = Layout()
    layout.split_column(
        Layout(cols,          name='stats',     ratio=3),
        Layout(t_comparison,  name='comp',      ratio=2),
        Layout(t_scans,       name='scans',     ratio=2),
    )

    return Panel(layout, title=title, border_style='bright_green')


# --------------------------------------------------------------------------
# Point d'entree
# --------------------------------------------------------------------------
def start():
    global docker_scanner

    console.print("\n[bold cyan]VirusTotal Scanner — Terminal Live[/bold cyan]")
    console.print("=" * 60)

    if not os.getenv('VIRUSTOTAL_API_KEY'):
        console.print("[yellow]  VIRUSTOTAL_API_KEY non defini — mode simulation[/yellow]")
    else:
        console.print("[green]  Cle API VirusTotal trouvee[/green]")

    # Docker
    docker_scanner = DockerVirusTotalScanner()
    if docker_scanner.connected:
        if docker_scanner.start_container("virustotal-docker"):
            console.print("[green]  ✓ Conteneur Docker lance[/green]")
        else:
            console.print("[red]  ✗ Erreur lancement Docker[/red]")
    else:
        console.print("[yellow]  ⚠️  Docker non disponible[/yellow]")

    # Scanners
    vm_scanner.process_scans()
    simulator.process_scans()

    # Fichiers de test
    test_files = [
        ('test1.bin', 'clean'),
        ('test2.exe', 'suspicious'),
        ('test3.txt', 'clean'),
        ('test4.dll', 'malicious'),
        ('test5.zip', 'clean'),
    ]

    console.print("\n[bold]Ajout de fichiers a scanner...[/bold]")
    
    for i, (filename, threat_type) in enumerate(test_files):
        # Créer un fichier temporaire réel
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
            tmp.write(b'TEST_BINARY_CONTENT_' * 50)
            tmp_path = tmp.name

        # VM Scanner
        vm_scanner.add_scan(filename, 256 * 1024)
        
        # Simulator
        simulator.add_scan(filename, threat_type)
        
        # Docker Scanner
        if docker_scanner and docker_scanner.connected and docker_scanner.container:
            def scan_docker(path):
                docker_scanner.scan_in_container(path)
            
            scan_thread = threading.Thread(target=scan_docker, args=(tmp_path,), daemon=True)
            scan_thread.start()
        
        console.print(f"  + {filename} ({threat_type})")

    start_time = time.time()
    console.print("\n[green]Simulation lancee — Ctrl+C pour arreter[/green]\n")

    try:
        with Live(build_layout(0), refresh_per_second=2, console=console) as live:
            while True:
                elapsed = time.time() - start_time
                live.update(build_layout(elapsed))
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        vm_scanner.stop()
        simulator.stop()
        if docker_scanner:
            docker_scanner.cleanup()
        console.print("\n[green]Simulation terminee[/green]")


if __name__ == '__main__':
    start()