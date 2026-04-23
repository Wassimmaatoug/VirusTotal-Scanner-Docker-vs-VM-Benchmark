# ==============================================================
#  VirusTotal Simulation Launcher
#  run.ps1 — version corrigee
#
#  UTILISATION :
#    Clic droit -> "Executer avec PowerShell"
#    ou depuis un terminal :
#      powershell -ExecutionPolicy Bypass -File .\run.ps1
# ==============================================================

# CORRECTION : forcer la politique d'execution pour ce processus uniquement
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

$ErrorActionPreference = "Stop"

Write-Host "`nVirusTotal Simulation Launcher" -ForegroundColor Cyan
Write-Host "=========================================`n" -ForegroundColor Cyan

# --------------------------------------------------------------
# 1. Verification Docker
# --------------------------------------------------------------
Write-Host "[1/6] Verification Docker..." -ForegroundColor Yellow
try {
    $dockerVer = docker --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Docker introuvable" }
    Write-Host "      OK : $dockerVer" -ForegroundColor Green
} catch {
    Write-Host "ERREUR : Docker non installe ou daemon non demarre." -ForegroundColor Red
    Write-Host "         https://www.docker.com/products/docker-desktop" -ForegroundColor Red
    Read-Host "`nAppuyez sur Entree pour quitter"
    exit 1
}

# --------------------------------------------------------------
# 2. Verification Python
# --------------------------------------------------------------
Write-Host "[2/6] Verification Python..." -ForegroundColor Yellow
try {
    $pyVer = python --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Python introuvable" }
    Write-Host "      OK : $pyVer" -ForegroundColor Green
} catch {
    Write-Host "ERREUR : Python non installe ou absent du PATH." -ForegroundColor Red
    Write-Host "         https://www.python.org/downloads/" -ForegroundColor Red
    Read-Host "`nAppuyez sur Entree pour quitter"
    exit 1
}

# --------------------------------------------------------------
# 3. Verification .env
# --------------------------------------------------------------
Write-Host "[3/6] Verification .env..." -ForegroundColor Yellow
if (-not (Test-Path ".env")) {
    Write-Host "      .env absent — creation d'un modele..." -ForegroundColor Yellow
    @"
# Remplissez votre cle API VirusTotal (https://www.virustotal.com/gui/my-apikey)
VIRUSTOTAL_API_KEY=VOTRE_CLE_ICI
VIRUSTOTAL_API_URL=https://www.virustotal.com/api/v3
"@ | Out-File -FilePath ".env" -Encoding UTF8
    Write-Host "      Editez le fichier .env puis relancez." -ForegroundColor Red
    Read-Host "`nAppuyez sur Entree pour quitter"
    exit 1
}

$envContent = Get-Content ".env" -Raw
if ($envContent -match "VIRUSTOTAL_API_KEY=VOTRE_CLE_ICI" -or
    $envContent -notmatch "VIRUSTOTAL_API_KEY=\S") {
    Write-Host "      ATTENTION : cle API non definie — mode simulation uniquement" -ForegroundColor Yellow
} else {
    Write-Host "      OK : cle API trouvee" -ForegroundColor Green
}

# --------------------------------------------------------------
# 4. Environnement virtuel + dependances
# --------------------------------------------------------------
Write-Host "[4/6] Environnement Python..." -ForegroundColor Yellow

if (-not (Test-Path "venv")) {
    Write-Host "      Creation du venv..." -ForegroundColor Green
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERREUR : impossible de creer le venv." -ForegroundColor Red
        Read-Host "`nAppuyez sur Entree pour quitter"
        exit 1
    }
}

$activateScript = ".\venv\Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    Write-Host "ERREUR : venv corrompu. Supprimez le dossier 'venv' et relancez." -ForegroundColor Red
    Read-Host "`nAppuyez sur Entree pour quitter"
    exit 1
}

. $activateScript
Write-Host "      venv active" -ForegroundColor Green

Write-Host "      Installation des dependances..." -ForegroundColor Green
pip install -q --upgrade pip
pip install -q -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR : echec pip install. Verifiez votre connexion." -ForegroundColor Red
    Read-Host "`nAppuyez sur Entree pour quitter"
    exit 1
}
Write-Host "      Dependances OK" -ForegroundColor Green

# --------------------------------------------------------------
# 5. Build de l'image Docker
# --------------------------------------------------------------
Write-Host "[5/6] Build de l'image Docker 'virustotal-sim'..." -ForegroundColor Yellow

if (-not (Test-Path "Dockerfile")) {
    Write-Host "      ATTENTION : Dockerfile absent — fallback python:3.11-slim" -ForegroundColor Yellow
} else {
    docker build -t virustotal-sim .
    if ($LASTEXITCODE -ne 0) {
        Write-Host "      ATTENTION : docker build a echoue — fallback python:3.11-slim" -ForegroundColor Yellow
    } else {
        Write-Host "      Image 'virustotal-sim' buildee avec succes" -ForegroundColor Green
    }
}

# --------------------------------------------------------------
# 6. Choix du mode
# --------------------------------------------------------------
Write-Host "`n[6/6] Choix du mode de lancement..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  [1] Dashboard graphique  (live_dashboard.py)" -ForegroundColor Cyan
Write-Host "  [2] Terminal live        (live_terminal.py)"  -ForegroundColor Cyan
Write-Host ""
$choice = Read-Host "Votre choix (1 ou 2, defaut=1)"

switch ($choice) {
    "2"     { $script = "live_terminal.py"  }
    default { $script = "live_dashboard.py" }
}

# --------------------------------------------------------------
# Lancement
# --------------------------------------------------------------
Write-Host "`n=========================================`n" -ForegroundColor Cyan
Write-Host "Lancement de $script ..." -ForegroundColor Green
Write-Host "Ctrl+C pour arreter`n" -ForegroundColor DarkGray

python $script
$exitCode = $LASTEXITCODE

Write-Host "`n=========================================" -ForegroundColor Cyan
if ($exitCode -eq 0) {
    Write-Host "Simulation terminee normalement." -ForegroundColor Green
} else {
    Write-Host "Le script s'est termine avec l'erreur : $exitCode" -ForegroundColor Red
    Write-Host "Consultez les messages ci-dessus pour plus de details."  -ForegroundColor Yellow
}

Read-Host "`nAppuyez sur Entree pour fermer"
