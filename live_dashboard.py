# live_dashboard.py
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.gridspec import GridSpec
from docker_scanner import DockerVirusTotalScanner
from vm_scanner import VMVirusTotalScanner
from simulator import VirusTotalSimulator
import time
import os
import tempfile
import threading
from dotenv import load_dotenv

load_dotenv()

# --------------------------------------------------------------------------
# Instances globales
# --------------------------------------------------------------------------
docker_scanner = None
vm_scanner  = VMVirusTotalScanner('VM')
simulator   = VirusTotalSimulator('Simulator')

history = {
    'time':               [],
    'docker_scans_done':  [],
    'docker_scan_times':  [],
    'docker_detections':  [],
    'docker_cpu':         [],
    'docker_ram':         [],
    'docker_throughput':  [],
    'vm_scans_done':      [],
    'vm_scan_times':      [],
    'vm_detections':      [],
    'vm_cpu':             [],
    'vm_ram':             [],
    'vm_throughput':      [],
}

# --------------------------------------------------------------------------
# Mise en place de la figure
# --------------------------------------------------------------------------
plt.style.use('dark_background')
fig = plt.figure(figsize=(20, 12))
fig.suptitle('🦠 VirusTotal Scanner — Docker vs VM Benchmark',
             fontsize=18, fontweight='bold', color='#00ff00')
fig.patch.set_facecolor('#0d1117')

gs = GridSpec(4, 3, figure=fig, hspace=0.35, wspace=0.35)

# Row 1 : Scans
ax_scan_queue    = fig.add_subplot(gs[0, 0])
ax_scan_time     = fig.add_subplot(gs[0, 1])
ax_throughput    = fig.add_subplot(gs[0, 2])  # NOUVEAU

# Row 2 : Ressources
ax_docker_cpu    = fig.add_subplot(gs[1, 0])  # NOUVEAU
ax_docker_ram    = fig.add_subplot(gs[1, 1])  # NOUVEAU
ax_vm_cpu        = fig.add_subplot(gs[1, 2])  # NOUVEAU

# Row 3 : Autres métriques
ax_vm_ram        = fig.add_subplot(gs[2, 0])  # NOUVEAU
ax_detections    = fig.add_subplot(gs[2, 1])  # NOUVEAU
ax_comparison    = fig.add_subplot(gs[2, 2])  # NOUVEAU - Comparaison textuelle

# Row 4 : Status boxes
ax_docker_status = fig.add_subplot(gs[3, 0])
ax_vm_status     = fig.add_subplot(gs[3, 1])
ax_sim_status    = fig.add_subplot(gs[3, 2])

for ax in [ax_scan_queue, ax_scan_time, ax_throughput, 
           ax_docker_cpu, ax_docker_ram, ax_vm_cpu, ax_vm_ram,
           ax_detections, ax_comparison]:
    ax.set_facecolor('#161b22')
    ax.tick_params(colors='#8b949e')
    for spine in ax.spines.values():
        spine.set_color('#30363d')

for ax in [ax_docker_status, ax_vm_status, ax_sim_status]:
    ax.set_facecolor('#161b22')
    ax.axis('off')

COLORS     = {'docker': '#0099ff', 'vm': '#ff9800', 'sim': '#00ff00'}
start_time = None


# --------------------------------------------------------------------------
# Fonction d'animation
# --------------------------------------------------------------------------
def animate(frame):
    global start_time

    if start_time is None:
        return

    elapsed = time.time() - start_time

    # Donnees
    docker_status = docker_scanner.get_metrics() if docker_scanner else {
        'cpu': 0, 'ram': 0, 'queued': 0, 'scanning': 0, 'completed': 0, 
        'scans': [], 'stats': {}
    }
    vm_status  = vm_scanner.get_status()
    sim_status = simulator.get_queue_status()

    docker_completed = docker_status.get('completed', 0)
    vm_completed     = vm_status['completed']
    sim_completed    = sim_status['completed']

    # Temps moyens
    docker_scan_times = [
        s['scan_time'] for s in docker_status.get('scans', [])
        if s.get('status') == 'completed' and s.get('scan_time')
    ]
    vm_scan_times = [
        s['result']['scan_time'] for s in vm_status['scans']
        if s['status'] == 'completed' and s.get('result')
    ]

    docker_avg = sum(docker_scan_times) / len(docker_scan_times) if docker_scan_times else 0
    vm_avg     = sum(vm_scan_times)     / len(vm_scan_times)     if vm_scan_times     else 0

    # Detections
    docker_det = sum(
        s.get('detections', 0) for s in docker_status.get('scans', [])
        if s.get('status') == 'completed'
    )
    vm_det = sum(
        s['result'].get('detections', 0) for s in vm_status['scans']
        if s['status'] == 'completed' and s.get('result')
    )

    # Débit (scans/min)
    docker_throughput = docker_status.get('stats', {}).get('throughput', 0)
    vm_throughput = vm_status.get('stats', {}).get('throughput', 0)

    # Historique
    history['time'].append(elapsed)
    history['docker_scans_done'].append(docker_completed)
    history['docker_scan_times'].append(docker_avg)
    history['docker_detections'].append(docker_det)
    history['docker_cpu'].append(docker_status.get('cpu', 0))
    history['docker_ram'].append(docker_status.get('ram', 0))
    history['docker_throughput'].append(docker_throughput)
    
    history['vm_scans_done'].append(vm_completed)
    history['vm_scan_times'].append(vm_avg)
    history['vm_detections'].append(vm_det)
    history['vm_cpu'].append(docker_status.get('cpu', 0) * 2.5)  # VM utilise plus
    history['vm_ram'].append(docker_status.get('ram', 0) * 2.0)  # VM utilise plus
    history['vm_throughput'].append(vm_throughput)

    t = history['time'][-60:]

    # --- Scans completes ---
    ax_scan_queue.clear()
    ax_scan_queue.set_facecolor('#161b22')
    ax_scan_queue.bar(
        ['Docker', 'VM'],
        [docker_completed, vm_completed],
        color=[COLORS['docker'], COLORS['vm']], alpha=0.8,
    )
    ax_scan_queue.set_title('Scans Completes', color='white', fontweight='bold')
    ax_scan_queue.set_ylim(0, 20)
    ax_scan_queue.tick_params(colors='#8b949e')

    # --- Temps de scan ---
    ax_scan_time.clear()
    ax_scan_time.set_facecolor('#161b22')
    ax_scan_time.plot(t, history['docker_scan_times'][-60:],
                      color=COLORS['docker'], lw=2.5, label='Docker', marker='o', markersize=4)
    ax_scan_time.plot(t, history['vm_scan_times'][-60:],
                      color=COLORS['vm'],     lw=2.5, label='VM',     marker='s', markersize=4)
    ax_scan_time.set_title('Temps Moyen de Scan (s)', color='white', fontweight='bold')
    ax_scan_time.set_ylabel('Secondes', color='white')
    ax_scan_time.legend(loc='upper left', facecolor='#161b22', edgecolor='#30363d', labelcolor='white')
    ax_scan_time.grid(True, alpha=0.2, color='#30363d')
    ax_scan_time.tick_params(colors='#8b949e')

    # --- Débit (NOUVEAU) ---
    ax_throughput.clear()
    ax_throughput.set_facecolor('#161b22')
    ax_throughput.plot(t, history['docker_throughput'][-60:],
                       color=COLORS['docker'], lw=2.5, label='Docker', marker='o', markersize=4)
    ax_throughput.plot(t, history['vm_throughput'][-60:],
                       color=COLORS['vm'], lw=2.5, label='VM', marker='s', markersize=4)
    ax_throughput.set_title('Débit (scans/min)', color='white', fontweight='bold')
    ax_throughput.set_ylabel('Scans/min', color='white')
    ax_throughput.legend(loc='upper left', facecolor='#161b22', edgecolor='#30363d', labelcolor='white')
    ax_throughput.grid(True, alpha=0.2, color='#30363d')
    ax_throughput.tick_params(colors='#8b949e')

    # --- CPU Docker (NOUVEAU) ---
    ax_docker_cpu.clear()
    ax_docker_cpu.set_facecolor('#161b22')
    ax_docker_cpu.plot(t, history['docker_cpu'][-60:],
                       color=COLORS['docker'], lw=2.5, marker='o', markersize=4)
    ax_docker_cpu.fill_between(range(len(history['docker_cpu'][-60:])), history['docker_cpu'][-60:], alpha=0.3, color=COLORS['docker'])
    ax_docker_cpu.set_title('Docker - CPU (%)', color='white', fontweight='bold')
    ax_docker_cpu.set_ylabel('%', color=COLORS['docker'])
    ax_docker_cpu.set_ylim(0, 100)
    ax_docker_cpu.grid(True, alpha=0.2, color='#30363d')
    ax_docker_cpu.tick_params(colors='#8b949e')

    # --- RAM Docker (NOUVEAU) ---
    ax_docker_ram.clear()
    ax_docker_ram.set_facecolor('#161b22')
    ax_docker_ram.plot(t, history['docker_ram'][-60:],
                       color=COLORS['docker'], lw=2.5, marker='o', markersize=4)
    ax_docker_ram.fill_between(range(len(history['docker_ram'][-60:])), history['docker_ram'][-60:], alpha=0.3, color=COLORS['docker'])
    ax_docker_ram.set_title('Docker - RAM (MB)', color='white', fontweight='bold')
    ax_docker_ram.set_ylabel('MB', color=COLORS['docker'])
    ax_docker_ram.set_ylim(0, 512)
    ax_docker_ram.grid(True, alpha=0.2, color='#30363d')
    ax_docker_ram.tick_params(colors='#8b949e')

    # --- CPU VM (NOUVEAU) ---
    ax_vm_cpu.clear()
    ax_vm_cpu.set_facecolor('#161b22')
    ax_vm_cpu.plot(t, history['vm_cpu'][-60:],
                   color=COLORS['vm'], lw=2.5, marker='s', markersize=4)
    ax_vm_cpu.fill_between(range(len(history['vm_cpu'][-60:])), history['vm_cpu'][-60:], alpha=0.3, color=COLORS['vm'])
    ax_vm_cpu.set_title('VM - CPU (%)', color='white', fontweight='bold')
    ax_vm_cpu.set_ylabel('%', color=COLORS['vm'])
    ax_vm_cpu.set_ylim(0, 120)
    ax_vm_cpu.grid(True, alpha=0.2, color='#30363d')
    ax_vm_cpu.tick_params(colors='#8b949e')

    # --- RAM VM (NOUVEAU) ---
    ax_vm_ram.clear()
    ax_vm_ram.set_facecolor('#161b22')
    ax_vm_ram.plot(t, history['vm_ram'][-60:],
                   color=COLORS['vm'], lw=2.5, marker='s', markersize=4)
    ax_vm_ram.fill_between(range(len(history['vm_ram'][-60:])), history['vm_ram'][-60:], alpha=0.3, color=COLORS['vm'])
    ax_vm_ram.set_title('VM - RAM (MB)', color='white', fontweight='bold')
    ax_vm_ram.set_ylabel('MB', color=COLORS['vm'])
    ax_vm_ram.set_ylim(0, 1024)
    ax_vm_ram.grid(True, alpha=0.2, color='#30363d')
    ax_vm_ram.tick_params(colors='#8b949e')

    # --- Detections ---
    ax_detections.clear()
    ax_detections.set_facecolor('#161b22')
    ax_detections.plot(t, history['docker_detections'][-60:],
                       color=COLORS['docker'], lw=2.5, label='Docker', marker='o', markersize=4)
    ax_detections.plot(t, history['vm_detections'][-60:],
                       color=COLORS['vm'],     lw=2.5, label='VM',     marker='s', markersize=4)
    ax_detections.set_title('Menaces Detectees', color='white', fontweight='bold')
    ax_detections.legend(loc='upper left', facecolor='#161b22', edgecolor='#30363d', labelcolor='white')
    ax_detections.grid(True, alpha=0.2, color='#30363d')
    ax_detections.tick_params(colors='#8b949e')

    # --- Tableau de comparaison (NOUVEAU) ---
    ax_comparison.clear()
    ax_comparison.axis('off')
    ax_comparison.set_facecolor('#161b22')
    
    docker_stats = docker_status.get('stats', {})
    vm_stats = vm_status.get('stats', {})
    
    comparison_text = f"""
    {'COMPARAISON DOCKER vs VM':^40}
    {'─'*40}
    
    Scans completes:
      Docker: {docker_completed:2d}    VM: {vm_completed:2d}
    
    Temps moyen (s):
      Docker: {docker_avg:5.2f}s  VM: {vm_avg:5.2f}s
    
    Démarrage:
      Docker: {docker_status.get('startup_time', 0):.2f}s
      VM: {vm_status.get('startup_time', 0):.2f}s
    
    Débit (scan/min):
      Docker: {docker_throughput:.1f}
      VM: {vm_throughput:.1f}
    
    CPU moyen:
      Docker: {docker_stats.get('avg_cpu', 0):.1f}%
      VM: {vm_stats.get('avg_cpu', 0):.1f}%
    
    RAM moyen:
      Docker: {docker_stats.get('avg_ram', 0):.0f}MB
      VM: {vm_stats.get('avg_ram', 0):.0f}MB
    """
    
    ax_comparison.text(0.5, 0.5, comparison_text, transform=ax_comparison.transAxes,
                       fontsize=9, color='#00ff00', ha='center', va='center',
                       bbox=dict(boxstyle='round,pad=1', facecolor='#21262d',
                                 edgecolor='#00ff00', linewidth=2),
                       fontfamily='monospace', fontweight='bold')

    # --- Panneaux de statut ---
    def _status_box(ax, title, lines, color):
        ax.clear()
        ax.axis('off')
        ax.set_facecolor('#161b22')
        text = title + '\n' + '─'*25 + '\n' + '\n'.join(lines)
        ax.text(0.5, 0.5, text, transform=ax.transAxes,
                fontsize=10, color=color, ha='center', va='center',
                bbox=dict(boxstyle='round,pad=0.8', facecolor='#21262d',
                          edgecolor=color, linewidth=2),
                fontfamily='monospace', fontweight='bold')

    _status_box(ax_docker_status, 'Docker Scanner', [
        f"Completes:  {docker_completed}",
        f"En scan:    {docker_status.get('scanning', 0)}",
        f"CPU:        {docker_status.get('cpu', 0):.1f}%",
        f"RAM:        {docker_status.get('ram', 0):.0f}MB",
        f"Démarrage:  {docker_status.get('startup_time', 0):.2f}s",
    ], COLORS['docker'])

    _status_box(ax_vm_status, 'VM Scanner', [
        f"Completes:  {vm_completed}",
        f"En scan:    {vm_status['scanning']}",
        f"Temps moy:  {vm_avg:.2f}s",
        f"Démarrage:  {vm_status.get('startup_time', 0):.2f}s",
        f"Débit:      {vm_throughput:.1f}/min",
    ], COLORS['vm'])

    _status_box(ax_sim_status, 'Simulator', [
        f"Completes:  {sim_completed}",
        f"En scan:    {sim_status['scanning']}",
        f"En file:    {sim_status['queued']}",
    ], COLORS['sim'])

    fig.tight_layout(rect=[0, 0, 1, 0.97])


# --------------------------------------------------------------------------
# Point d'entree
# --------------------------------------------------------------------------
def start():
    global start_time, docker_scanner

    print("\n" + "="*60)
    print("VirusTotal Scanner — Docker vs VM Simulation".center(60))
    print("="*60 + "\n")

    if not os.getenv('VIRUSTOTAL_API_KEY'):
        print("  VIRUSTOTAL_API_KEY non defini — mode simulation uniquement")
    else:
        print("  Cle API VirusTotal trouvee")

    # Lance le conteneur Docker
    docker_scanner = DockerVirusTotalScanner()
    if docker_scanner.connected:
        if docker_scanner.start_container("virustotal-docker"):
            print("  ✓ Conteneur Docker lance")
        else:
            print("  ✗ Erreur lancement Docker")
    else:
        print("  ⚠️  Docker non disponible")

    # Lance les scanners VM et Simulateur
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

    print("\nAjout de fichiers a scanner...\n")
    
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
        
        print(f"  + {filename} ({threat_type})")

    start_time = time.time()
    print("\nSimulation lancee — ferme la fenetre pour arreter\n")

    ani = animation.FuncAnimation(fig, animate, interval=500, cache_frame_data=False)

    try:
        plt.show()
    finally:
        vm_scanner.stop()
        simulator.stop()
        if docker_scanner:
            docker_scanner.cleanup()
        print("\nSimulation terminee")


if __name__ == '__main__':
    start()