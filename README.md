# VirusTotal Scanner — Docker vs VM Benchmark

Projet de comparaison des performances entre un scanner VirusTotal exécuté dans un **conteneur Docker** et un scanner simulé en **environnement VM**. 

---

## Objectif

Mesurer et visualiser en temps réel les différences de performance (temps de démarrage, temps de scan, CPU, RAM, débit) entre deux environnements d'isolation :

| Environnement | Description |
|---|---|
| 🐳 **Docker** | Conteneur `python:3.11-slim` avec isolation légère |
| ⚙️ **VM** | Simulation d'un scanner sous machine virtuelle |
| 🤖 **Simulator** | Simulation pure (sans infrastructure), référence de base |

---

## Architecture

```
virustotal-benchmark/
├── docker_scanner.py      # Scanner exécuté dans un conteneur Docker
├── vm_scanner.py          # Scanner simulant un environnement VM
├── simulator.py           # Simulateur VirusTotal (profils clean/suspicious/malicious)
├── metrics.py             # Collecteur de métriques (CPU, RAM, débit, temps de scan)
├── live_dashboard.py      # Dashboard graphique matplotlib (mode 1)
├── live_terminal.py       # Dashboard terminal Rich live (mode 2)
├── virustotal_scanner.py  # Client API VirusTotal v3 (mode réel)
├── Dockerfile             # Image Docker du scanner
├── requirements.txt       # Dépendances Python
├── run.ps1                # Lanceur PowerShell automatisé (Windows)
└── .env                   # Configuration clé API (à créer)
```

---

## Prérequis

| Outil | Version minimale | Lien |
|---|---|---|
| Python | 3.9+ | https://www.python.org/downloads/ |
| Docker Desktop | 20.x+ | https://www.docker.com/products/docker-desktop |
| PowerShell | 5.1+ (Windows uniquement) | Inclus dans Windows 10/11 |

---

## Installation

### 1. Cloner le projet

```bash
git clone https://github.com/votre-repo/VirusTotal-Scanner-Docker-vs-VM-Benchmark.git
cd VirusTotal-Scanner-Docker-vs-VM-Benchmark
```

### 2. Configurer le fichier `.env`

Renommer `_env` en `.env` et renseigner votre clé API :

```env
VIRUSTOTAL_API_KEY=votre_clé_api_ici
VIRUSTOTAL_API_URL=https://www.virustotal.com/api/v3
DOCKER_IMAGE=python:3.9-slim
```

> 💡 Clé API gratuite disponible sur : https://www.virustotal.com/gui/my-apikey  
> Sans clé API, le projet fonctionne en **mode simulation pure**.

### 3. Créer un environnement virtuel Python

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 4. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 5. Builder l'image Docker

```bash
docker build -t virustotal-sim .
```

---

## Lancement

### Option A — Lanceur automatique PowerShell (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

Le script effectue automatiquement :
1. Vérification Docker
2. Vérification Python
3. Vérification / création du `.env`
4. Création du venv + installation des dépendances
5. Build de l'image Docker
6. Choix du mode d'affichage (dashboard ou terminal)

### Option B — Lancement manuel

**Dashboard graphique (matplotlib) :**
```bash
python live_dashboard.py
```

**Terminal live (Rich) :**
```bash
python live_terminal.py
```

---

## Modes d'affichage

### Mode 1 — Dashboard graphique (`live_dashboard.py`)

Interface matplotlib avec graphiques en temps réel :
- Courbes CPU et RAM par environnement
- Histogrammes des temps de scan
- Tableau de comparaison Docker vs VM

### Mode 2 — Terminal live (`live_terminal.py`)

Interface Rich dans le terminal, rafraîchissement toutes les 500ms :

```
┌─ VirusTotal Scanner — Docker vs VM  |  t=12.3s ──────────────────┐
│  🐳 Docker Scanner   ⚙️ VM Scanner   🤖 Simulator                  │
│  📊 Comparaison Docker vs VM                                       │
│  🔍 Scans en cours                                                 │
└────────────────────────────────────────────────────────────────────┘
```

---

## Métriques collectées

| Métrique | Description |
|---|---|
| `startup_time` | Temps de démarrage de l'environnement (secondes) |
| `avg_scan_time` | Temps moyen par scan (secondes) |
| `min/max_scan_time` | Bornes des temps de scan |
| `avg_cpu` | Utilisation CPU moyenne (%) |
| `avg_ram` | Consommation RAM moyenne (MB) |
| `throughput` | Débit en scans/minute |
| `total_scans` | Nombre total de scans complétés |

---

## Profils de menace (Simulator)

| Profil | Taux de détection | Temps de scan |
|---|---|---|
| `clean` | 0/70 | 0.8 – 1.5s |
| `suspicious` | 1–5/70 | 1.2 – 2.0s |
| `malicious` | 10–50/70 | 1.5 – 3.0s |

---

## API VirusTotal (mode réel)

Le module `virustotal_scanner.py` implémente le client API v3 avec :

- **Scan de fichier** — soumission via `POST /files`
- **Récupération de résultats** — via `GET /analyses/{id}`
- **Scan par hash SHA-256** — via `GET /files/{hash}` (plus rapide, sans soumission)
- **Rate limiting** — respect automatique de la limite gratuite (4 req/min)

> ⚠️ Le plan gratuit VirusTotal est limité à **4 requêtes/minute** et **500 requêtes/jour**.

---

## Dépendances Python

```
matplotlib==3.7.1      # Graphiques dashboard
rich==13.3.5           # Interface terminal live
psutil==5.9.5          # Métriques système
docker==6.1.3          # API Docker Python
pandas==2.0.3          # Manipulation de données
numpy==1.24.3          # Calculs numériques
requests==2.31.0       # Requêtes HTTP (API VirusTotal)
python-dotenv==1.0.0   # Chargement .env
Pillow==10.0.0         # Support images matplotlib
```


## Licence

Projet académique — usage éducatif uniquement.
