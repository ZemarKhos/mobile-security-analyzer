#!/usr/bin/env python3
"""
MobAI - Mobile Security Analyzer
Kapsamli Kurulum ve Yonetim Araci
Version: 2.1.0

Kullanim:
    ./mobai install          # Interaktif kurulum
    ./mobai start            # Servisleri baslat
    ./mobai stop             # Servisleri durdur
    ./mobai status           # Durum kontrolu
    ./mobai --help           # Yardim
"""

import os
import sys
import subprocess
import shutil
import platform
import socket
import secrets
import json
import signal
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Tuple

# Renk destegi icin Rich kontrolu
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.markdown import Markdown
    from rich import box
    import click
    import questionary
    from questionary import Style
    import requests
    import psutil
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("UYARI: Rich kutuphanesi bulunamadi. Basit mod kullaniliyor.")
    print("Tam ozellikleri aktive etmek icin: pip install rich click questionary requests psutil")

# ============================================
# Sabitler
# ============================================

VERSION = "2.1.0"
PROJECT_NAME = "MobAI"
PROJECT_FULL_NAME = "Mobile Security Analyzer"

# Dizinler
SCRIPT_DIR = Path(__file__).parent.absolute()
BACKEND_DIR = SCRIPT_DIR / "backend"
FRONTEND_DIR = SCRIPT_DIR / "frontend"
CONFIG_DIR = SCRIPT_DIR / "config"
DATA_DIR = SCRIPT_DIR / "data"
UPLOADS_DIR = SCRIPT_DIR / "uploads"
LOGS_DIR = SCRIPT_DIR / "logs"

# Varsayilan portlar
DEFAULT_BACKEND_PORT = 8000
DEFAULT_FRONTEND_PORT = 5173
DEFAULT_PROD_PORT = 3000

# APKTool
APKTOOL_VERSION = "2.9.3"
APKTOOL_URL = f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/apktool_{APKTOOL_VERSION}.jar"
APKTOOL_WRAPPER_URL = "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"

# PID dosyalari
BACKEND_PID_FILE = SCRIPT_DIR / ".backend.pid"
FRONTEND_PID_FILE = SCRIPT_DIR / ".frontend.pid"

# Questionary stili
CUSTOM_STYLE = Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'fg:white bold'),
    ('answer', 'fg:green bold'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:green'),
    ('separator', 'fg:gray'),
    ('instruction', 'fg:gray'),
]) if RICH_AVAILABLE else None

# ============================================
# Console ve Yardimci Fonksiyonlar
# ============================================

console = Console() if RICH_AVAILABLE else None

def print_banner():
    """ASCII art banner goster"""
    banner = """
[bold cyan]
  __  __       _        _    ___
 |  \\/  | ___ | |__    / \\  |_ _|
 | |\\/| |/ _ \\| '_ \\  / _ \\  | |
 | |  | | (_) | |_) |/ ___ \\ | |
 |_|  |_|\\___/|_.__//_/   \\_\\___|
[/bold cyan]
[dim]Mobile Security Analyzer v{version}[/dim]
[dim]Kapsamli Kurulum ve Yonetim Araci[/dim]
""".format(version=VERSION)

    if RICH_AVAILABLE:
        console.print(banner)
    else:
        print(f"\n{'='*50}")
        print(f"  MobAI - Mobile Security Analyzer v{VERSION}")
        print(f"{'='*50}\n")

def log_info(message: str):
    if RICH_AVAILABLE:
        console.print(f"[blue][INFO][/blue] {message}")
    else:
        print(f"[INFO] {message}")

def log_success(message: str):
    if RICH_AVAILABLE:
        console.print(f"[green][OK][/green] {message}")
    else:
        print(f"[OK] {message}")

def log_warning(message: str):
    if RICH_AVAILABLE:
        console.print(f"[yellow][WARN][/yellow] {message}")
    else:
        print(f"[WARN] {message}")

def log_error(message: str):
    if RICH_AVAILABLE:
        console.print(f"[red][ERROR][/red] {message}")
    else:
        print(f"[ERROR] {message}")

def run_command(cmd: List[str], cwd: Optional[Path] = None, capture: bool = True, env: Optional[Dict] = None) -> Tuple[int, str, str]:
    """Komut calistir ve sonuc don"""
    try:
        process_env = os.environ.copy()
        if env:
            process_env.update(env)

        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=capture,
            text=True,
            env=process_env
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)

def check_command(cmd: str) -> bool:
    """Komutun sistemde mevcut olup olmadigini kontrol et"""
    return shutil.which(cmd) is not None

def get_python_cmd() -> str:
    """Python komutunu bul"""
    for cmd in ['python3', 'python']:
        if check_command(cmd):
            return cmd
    return 'python3'

def get_command_version(cmd: str, version_flag: str = '--version') -> Optional[str]:
    """Komut versiyonunu al"""
    try:
        result = subprocess.run([cmd, version_flag], capture_output=True, text=True)
        return result.stdout.strip() or result.stderr.strip()
    except:
        return None

def is_port_available(port: int) -> bool:
    """Portun kullanilabilir olup olmadigini kontrol et"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', port))
            return True
        except OSError:
            return False

def get_process_on_port(port: int) -> Optional[int]:
    """Belirtilen portu kullanan process'in PID'ini bul"""
    if RICH_AVAILABLE:
        for conn in psutil.net_connections():
            if conn.laddr.port == port and conn.status == 'LISTEN':
                return conn.pid
    else:
        # lsof ile kontrol
        try:
            result = subprocess.run(
                ['lsof', '-i', f':{port}', '-t'],
                capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip().split('\n')[0])
        except:
            pass
    return None

# ============================================
# Sistem Kontrol Sinifi
# ============================================

class SystemChecker:
    """Sistem gereksinimlerini kontrol eden sinif"""

    def __init__(self):
        self.os_info = self._detect_os()
        self.arch = platform.machine()
        self.python_version = platform.python_version()

    def _detect_os(self) -> Dict:
        """Isletim sistemini tespit et"""
        system = platform.system().lower()
        info = {
            'system': system,
            'name': 'unknown',
            'version': '',
            'package_manager': None
        }

        if system == 'linux':
            try:
                with open('/etc/os-release') as f:
                    for line in f:
                        if line.startswith('ID='):
                            info['name'] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('VERSION_ID='):
                            info['version'] = line.split('=')[1].strip().strip('"')
            except:
                pass

            # Paket yoneticisi tespiti
            if info['name'] in ['ubuntu', 'debian', 'linuxmint', 'pop']:
                info['package_manager'] = 'apt'
            elif info['name'] in ['fedora', 'rhel', 'centos', 'rocky', 'almalinux']:
                info['package_manager'] = 'dnf'
            elif info['name'] in ['arch', 'manjaro', 'endeavouros']:
                info['package_manager'] = 'pacman'
            elif info['name'].startswith('opensuse'):
                info['package_manager'] = 'zypper'

        elif system == 'darwin':
            info['name'] = 'macos'
            info['version'] = platform.mac_ver()[0]
            info['package_manager'] = 'brew'

        elif system == 'windows':
            info['name'] = 'windows'
            info['version'] = platform.version()

        return info

    def check_all(self) -> Dict:
        """Tum sistem gereksinimlerini kontrol et"""
        results = {
            'os': self._check_os(),
            'python': self._check_python(),
            'node': self._check_node(),
            'npm': self._check_npm(),
            'java': self._check_java(),
            'git': self._check_git(),
            'docker': self._check_docker(),
            'apktool': self._check_apktool(),
            'disk': self._check_disk(),
            'memory': self._check_memory(),
            'ports': self._check_ports(),
        }
        return results

    def _check_os(self) -> Dict:
        return {
            'name': 'Operating System',
            'status': True,
            'value': f"{self.os_info['name']} {self.os_info['version']}",
            'required': 'Linux/macOS/WSL'
        }

    def _check_python(self) -> Dict:
        version = self.python_version
        major, minor = map(int, version.split('.')[:2])
        ok = major >= 3 and minor >= 8
        return {
            'name': 'Python',
            'status': ok,
            'value': version,
            'required': '3.8+'
        }

    def _check_node(self) -> Dict:
        version = get_command_version('node', '-v')
        if version:
            version = version.replace('v', '')
            major = int(version.split('.')[0])
            ok = major >= 18
        else:
            ok = False
            version = 'Not found'
        return {
            'name': 'Node.js',
            'status': ok,
            'value': version,
            'required': '18+'
        }

    def _check_npm(self) -> Dict:
        version = get_command_version('npm', '-v')
        ok = version is not None
        return {
            'name': 'npm',
            'status': ok,
            'value': version or 'Not found',
            'required': 'Any'
        }

    def _check_java(self) -> Dict:
        version = get_command_version('java', '-version')
        ok = version is not None
        if version:
            # Java version string'den versiyon cikar
            import re
            match = re.search(r'version "?(\d+)', version)
            if match:
                version = match.group(1)
        return {
            'name': 'Java JDK',
            'status': ok,
            'value': version or 'Not found',
            'required': '11+'
        }

    def _check_git(self) -> Dict:
        version = get_command_version('git', '--version')
        ok = version is not None
        if version:
            version = version.replace('git version ', '')
        return {
            'name': 'Git',
            'status': ok,
            'value': version or 'Not found',
            'required': 'Any'
        }

    def _check_docker(self) -> Dict:
        version = get_command_version('docker', '--version')
        ok = version is not None
        if version:
            import re
            match = re.search(r'(\d+\.\d+\.\d+)', version)
            if match:
                version = match.group(1)
        return {
            'name': 'Docker',
            'status': ok,
            'value': version or 'Not found',
            'required': 'Optional'
        }

    def _check_apktool(self) -> Dict:
        ok = check_command('apktool')
        version = 'Not found'
        if ok:
            ver = get_command_version('apktool', '-version')
            if ver:
                version = ver.split('\n')[0]
        return {
            'name': 'APKTool',
            'status': ok,
            'value': version,
            'required': f'{APKTOOL_VERSION}'
        }

    def _check_disk(self) -> Dict:
        if RICH_AVAILABLE:
            usage = psutil.disk_usage(SCRIPT_DIR)
            free_gb = usage.free / (1024 ** 3)
        else:
            # df komutu ile kontrol
            try:
                result = subprocess.run(
                    ['df', '-B1', str(SCRIPT_DIR)],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        parts = lines[1].split()
                        free_gb = int(parts[3]) / (1024 ** 3)
                    else:
                        free_gb = 0
                else:
                    free_gb = 0
            except:
                free_gb = 0
        ok = free_gb >= 0.5  # 500MB
        return {
            'name': 'Disk Space',
            'status': ok,
            'value': f'{free_gb:.1f} GB free',
            'required': '500MB+'
        }

    def _check_memory(self) -> Dict:
        if RICH_AVAILABLE:
            mem = psutil.virtual_memory()
            total_gb = mem.total / (1024 ** 3)
            available_gb = mem.available / (1024 ** 3)
        else:
            # /proc/meminfo ile kontrol (Linux)
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = f.read()
                total_gb = 0
                available_gb = 0
                for line in meminfo.split('\n'):
                    if line.startswith('MemTotal:'):
                        total_gb = int(line.split()[1]) / (1024 ** 2)
                    elif line.startswith('MemAvailable:'):
                        available_gb = int(line.split()[1]) / (1024 ** 2)
            except:
                total_gb = 0
                available_gb = 0
        ok = total_gb >= 2
        return {
            'name': 'Memory',
            'status': ok,
            'value': f'{available_gb:.1f} GB available / {total_gb:.1f} GB total',
            'required': '2GB+'
        }

    def _check_ports(self) -> Dict:
        ports = [DEFAULT_BACKEND_PORT, DEFAULT_FRONTEND_PORT, DEFAULT_PROD_PORT]
        available = [p for p in ports if is_port_available(p)]
        ok = len(available) >= 2
        return {
            'name': 'Ports',
            'status': ok,
            'value': f'{len(available)}/{len(ports)} available ({", ".join(map(str, available))})',
            'required': f'{DEFAULT_BACKEND_PORT}, {DEFAULT_FRONTEND_PORT}'
        }

    def display_results(self, results: Dict):
        """Sonuclari tablo olarak goster"""
        if RICH_AVAILABLE:
            table = Table(title="Sistem Gereksinimleri", box=box.ROUNDED)
            table.add_column("Bileşen", style="cyan")
            table.add_column("Durum", justify="center")
            table.add_column("Değer", style="white")
            table.add_column("Gereksinim", style="dim")

            for key, check in results.items():
                status = "[green]✓[/green]" if check['status'] else "[red]✗[/red]"
                table.add_row(check['name'], status, check['value'], check['required'])

            console.print(table)
        else:
            print("\nSistem Gereksinimleri:")
            print("-" * 60)
            for key, check in results.items():
                status = "OK" if check['status'] else "FAIL"
                print(f"  [{status}] {check['name']}: {check['value']} (Gerekli: {check['required']})")
            print()

# ============================================
# Bagimlilk Yoneticisi
# ============================================

class DependencyManager:
    """Sistem ve Python bagimliliklerini yoneten sinif"""

    def __init__(self, system_checker: SystemChecker):
        self.checker = system_checker
        self.os_info = system_checker.os_info

    def install_system_packages(self, packages: List[str]) -> bool:
        """Sistem paketlerini kur"""
        pm = self.os_info['package_manager']
        if not pm:
            log_error("Paket yoneticisi tespit edilemedi!")
            return False

        cmd = []
        if pm == 'apt':
            cmd = ['sudo', 'apt', 'update']
            run_command(cmd)
            cmd = ['sudo', 'apt', 'install', '-y'] + packages
        elif pm == 'dnf':
            cmd = ['sudo', 'dnf', 'install', '-y'] + packages
        elif pm == 'pacman':
            cmd = ['sudo', 'pacman', '-S', '--noconfirm'] + packages
        elif pm == 'brew':
            cmd = ['brew', 'install'] + packages
        else:
            log_error(f"Desteklenmeyen paket yoneticisi: {pm}")
            return False

        log_info(f"Paketler kuruluyor: {', '.join(packages)}")
        code, _, err = run_command(cmd)
        if code != 0:
            log_error(f"Paket kurulumu basarisiz: {err}")
            return False
        return True

    def install_python_deps(self, venv_path: Path, requirements_file: Path) -> bool:
        """Python bagimlilaklarini kur"""
        pip_cmd = str(venv_path / 'bin' / 'pip')

        # pip guncelle
        log_info("pip guncelleniyor...")
        run_command([pip_cmd, 'install', '--upgrade', 'pip', '-q'])

        # Bagimliliklari kur
        log_info(f"Python bagimliliklari kuruluyor: {requirements_file}")
        code, _, err = run_command([pip_cmd, 'install', '-r', str(requirements_file)])
        if code != 0:
            log_error(f"Python bagimliliklari kurulamadi: {err}")
            return False
        return True

    def install_node_deps(self, project_dir: Path) -> bool:
        """Node.js bagimlilaklarini kur"""
        log_info("Node.js bagimliliklari kuruluyor...")
        code, _, err = run_command(['npm', 'install'], cwd=project_dir)
        if code != 0:
            log_error(f"npm install basarisiz: {err}")
            return False
        return True

    def install_apktool(self) -> bool:
        """APKTool'u indir ve kur"""
        log_info(f"APKTool v{APKTOOL_VERSION} indiriliyor...")

        apktool_dir = Path('/usr/local/bin')
        jar_path = apktool_dir / 'apktool.jar'
        wrapper_path = apktool_dir / 'apktool'

        try:
            # JAR indir
            response = requests.get(APKTOOL_URL, stream=True)
            response.raise_for_status()

            temp_jar = Path('/tmp/apktool.jar')
            with open(temp_jar, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Wrapper indir
            response = requests.get(APKTOOL_WRAPPER_URL)
            response.raise_for_status()

            temp_wrapper = Path('/tmp/apktool')
            with open(temp_wrapper, 'w') as f:
                f.write(response.text)

            # /usr/local/bin'e kopyala (sudo gerekli)
            run_command(['sudo', 'mv', str(temp_jar), str(jar_path)])
            run_command(['sudo', 'mv', str(temp_wrapper), str(wrapper_path)])
            run_command(['sudo', 'chmod', '+x', str(wrapper_path)])

            log_success(f"APKTool v{APKTOOL_VERSION} kuruldu")
            return True

        except Exception as e:
            log_error(f"APKTool kurulumu basarisiz: {e}")
            return False

# ============================================
# Servis Yoneticisi
# ============================================

class ServiceManager:
    """Backend ve Frontend servislerini yoneten sinif"""

    def __init__(self):
        self.backend_pid = self._read_pid(BACKEND_PID_FILE)
        self.frontend_pid = self._read_pid(FRONTEND_PID_FILE)

    def _read_pid(self, pid_file: Path) -> Optional[int]:
        """PID dosyasindan pid oku"""
        try:
            if pid_file.exists():
                return int(pid_file.read_text().strip())
        except:
            pass
        return None

    def _write_pid(self, pid_file: Path, pid: int):
        """PID'i dosyaya yaz"""
        pid_file.write_text(str(pid))

    def _remove_pid(self, pid_file: Path):
        """PID dosyasini sil"""
        try:
            pid_file.unlink()
        except:
            pass

    def _is_process_running(self, pid: Optional[int]) -> bool:
        """Process'in calisip calismadigini kontrol et"""
        if pid is None:
            return False
        try:
            if RICH_AVAILABLE:
                process = psutil.Process(pid)
                return process.is_running()
            else:
                # psutil olmadan os.kill ile kontrol
                os.kill(pid, 0)
                return True
        except (OSError, ProcessLookupError):
            return False
        except:
            return False

    def start_backend(self, port: int = DEFAULT_BACKEND_PORT) -> bool:
        """Backend servisini baslat"""
        if self._is_process_running(self.backend_pid):
            log_warning(f"Backend zaten calisiyor (PID: {self.backend_pid})")
            return True

        log_info(f"Backend baslatiliyor (port: {port})...")

        # Virtual environment yolu
        venv_python = BACKEND_DIR / 'venv' / 'bin' / 'python'
        if not venv_python.exists():
            log_error("Backend virtual environment bulunamadi!")
            log_info("Kurulum icin: ./mobai install --backend")
            return False

        # Environment degiskenleri
        env = {
            'UPLOAD_DIR': str(UPLOADS_DIR),
            'DATA_DIR': str(DATA_DIR),
            'DATABASE_PATH': str(DATA_DIR / 'mobile_analyzer.db'),
        }

        # Uvicorn ile baslat
        cmd = [
            str(venv_python), '-m', 'uvicorn',
            'main:app',
            '--host', '0.0.0.0',
            '--port', str(port),
            '--reload'
        ]

        try:
            process = subprocess.Popen(
                cmd,
                cwd=BACKEND_DIR,
                env={**os.environ, **env},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )

            self._write_pid(BACKEND_PID_FILE, process.pid)
            self.backend_pid = process.pid

            # Saglik kontrolu icin bekle
            time.sleep(2)

            if self._is_process_running(process.pid):
                log_success(f"Backend baslatildi (PID: {process.pid})")
                return True
            else:
                log_error("Backend baslatildi ama hemen durdu!")
                return False

        except Exception as e:
            log_error(f"Backend baslatilamadi: {e}")
            return False

    def start_frontend(self, port: int = DEFAULT_FRONTEND_PORT, dev: bool = True) -> bool:
        """Frontend servisini baslat"""
        if self._is_process_running(self.frontend_pid):
            log_warning(f"Frontend zaten calisiyor (PID: {self.frontend_pid})")
            return True

        log_info(f"Frontend baslatiliyor (port: {port})...")

        # node_modules kontrolu
        if not (FRONTEND_DIR / 'node_modules').exists():
            log_error("Frontend bagimliliklari kurulmamis!")
            log_info("Kurulum icin: ./mobai install --frontend")
            return False

        cmd = ['npm', 'run', 'dev'] if dev else ['npm', 'run', 'preview']

        try:
            process = subprocess.Popen(
                cmd,
                cwd=FRONTEND_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )

            self._write_pid(FRONTEND_PID_FILE, process.pid)
            self.frontend_pid = process.pid

            time.sleep(2)

            if self._is_process_running(process.pid):
                log_success(f"Frontend baslatildi (PID: {process.pid})")
                return True
            else:
                log_error("Frontend baslatildi ama hemen durdu!")
                return False

        except Exception as e:
            log_error(f"Frontend baslatilamadi: {e}")
            return False

    def stop_backend(self) -> bool:
        """Backend servisini durdur"""
        if not self._is_process_running(self.backend_pid):
            log_warning("Backend zaten calismiyor")
            self._remove_pid(BACKEND_PID_FILE)
            return True

        log_info(f"Backend durduruluyor (PID: {self.backend_pid})...")

        try:
            if RICH_AVAILABLE:
                process = psutil.Process(self.backend_pid)
                # Alt processleri de durdur
                for child in process.children(recursive=True):
                    child.terminate()
                process.terminate()

                # Graceful shutdown icin bekle
                process.wait(timeout=5)
            else:
                # psutil olmadan - pkill ve os.kill kullan
                os.kill(self.backend_pid, signal.SIGTERM)
                time.sleep(2)
                # Hala calisiyorsa zorla durdur
                if self._is_process_running(self.backend_pid):
                    os.kill(self.backend_pid, signal.SIGKILL)

            self._remove_pid(BACKEND_PID_FILE)
            self.backend_pid = None
            log_success("Backend durduruldu")
            return True

        except Exception as e:
            # Timeout veya diger hatalar - zorla durdur
            try:
                if RICH_AVAILABLE and hasattr(e, '__class__') and e.__class__.__name__ == 'TimeoutExpired':
                    process.kill()
                else:
                    os.kill(self.backend_pid, signal.SIGKILL)
                self._remove_pid(BACKEND_PID_FILE)
                log_warning("Backend zorla durduruldu")
                return True
            except:
                log_error(f"Backend durdurulamadi: {e}")
                return False

    def stop_frontend(self) -> bool:
        """Frontend servisini durdur"""
        if not self._is_process_running(self.frontend_pid):
            log_warning("Frontend zaten calismiyor")
            self._remove_pid(FRONTEND_PID_FILE)
            return True

        log_info(f"Frontend durduruluyor (PID: {self.frontend_pid})...")

        try:
            if RICH_AVAILABLE:
                process = psutil.Process(self.frontend_pid)
                for child in process.children(recursive=True):
                    child.terminate()
                process.terminate()
                process.wait(timeout=5)
            else:
                # psutil olmadan - os.kill kullan
                os.kill(self.frontend_pid, signal.SIGTERM)
                time.sleep(2)
                if self._is_process_running(self.frontend_pid):
                    os.kill(self.frontend_pid, signal.SIGKILL)

            self._remove_pid(FRONTEND_PID_FILE)
            self.frontend_pid = None
            log_success("Frontend durduruldu")
            return True

        except Exception as e:
            # Timeout veya diger hatalar
            try:
                if RICH_AVAILABLE and hasattr(e, '__class__') and e.__class__.__name__ == 'TimeoutExpired':
                    process.kill()
                else:
                    os.kill(self.frontend_pid, signal.SIGKILL)
                self._remove_pid(FRONTEND_PID_FILE)
                log_warning("Frontend zorla durduruldu")
                return True
            except:
                log_error(f"Frontend durdurulamadi: {e}")
                return False

    def start_all(self) -> bool:
        """Tum servisleri baslat"""
        backend_ok = self.start_backend()
        frontend_ok = self.start_frontend()
        return backend_ok and frontend_ok

    def stop_all(self) -> bool:
        """Tum servisleri durdur"""
        backend_ok = self.stop_backend()
        frontend_ok = self.stop_frontend()
        return backend_ok and frontend_ok

    def restart_all(self) -> bool:
        """Tum servisleri yeniden baslat"""
        self.stop_all()
        time.sleep(1)
        return self.start_all()

    def get_status(self) -> Dict:
        """Servis durumlarini al"""
        backend_running = self._is_process_running(self.backend_pid)
        frontend_running = self._is_process_running(self.frontend_pid)

        status = {
            'backend': {
                'running': backend_running,
                'pid': self.backend_pid if backend_running else None,
                'port': DEFAULT_BACKEND_PORT,
                'url': f'http://localhost:{DEFAULT_BACKEND_PORT}'
            },
            'frontend': {
                'running': frontend_running,
                'pid': self.frontend_pid if frontend_running else None,
                'port': DEFAULT_FRONTEND_PORT,
                'url': f'http://localhost:{DEFAULT_FRONTEND_PORT}'
            }
        }

        # Backend saglik kontrolu
        if backend_running:
            try:
                response = requests.get(f'http://localhost:{DEFAULT_BACKEND_PORT}/api/health', timeout=2)
                status['backend']['healthy'] = response.status_code == 200
            except:
                status['backend']['healthy'] = False

        return status

    def display_status(self):
        """Durum bilgisini goster"""
        status = self.get_status()

        if RICH_AVAILABLE:
            table = Table(title="Servis Durumu", box=box.ROUNDED)
            table.add_column("Servis", style="cyan")
            table.add_column("Durum", justify="center")
            table.add_column("PID")
            table.add_column("URL")

            for name, info in status.items():
                if info['running']:
                    status_text = "[green]● Calisiyor[/green]"
                    pid_text = str(info['pid'])
                else:
                    status_text = "[red]○ Durdu[/red]"
                    pid_text = "-"

                table.add_row(
                    name.capitalize(),
                    status_text,
                    pid_text,
                    info['url']
                )

            console.print(table)
        else:
            print("\nServis Durumu:")
            print("-" * 50)
            for name, info in status.items():
                status_str = "RUNNING" if info['running'] else "STOPPED"
                print(f"  {name.capitalize()}: {status_str} (PID: {info.get('pid', '-')}) - {info['url']}")
            print()

# ============================================
# Veritabani Yoneticisi
# ============================================

class DatabaseManager:
    """Veritabani islemlerini yoneten sinif"""

    def __init__(self):
        self.db_path = DATA_DIR / 'mobile_analyzer.db'

    def backup(self, output_path: Optional[Path] = None) -> Optional[Path]:
        """Veritabanini yedekle"""
        if not self.db_path.exists():
            log_error("Veritabani bulunamadi!")
            return None

        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = SCRIPT_DIR / f'backup_{timestamp}.tar.gz'

        log_info(f"Yedekleme olusturuluyor: {output_path}")

        try:
            import tarfile
            with tarfile.open(output_path, 'w:gz') as tar:
                tar.add(self.db_path, arcname='mobile_analyzer.db')
                if UPLOADS_DIR.exists():
                    tar.add(UPLOADS_DIR, arcname='uploads')

            log_success(f"Yedekleme tamamlandi: {output_path}")
            return output_path

        except Exception as e:
            log_error(f"Yedekleme basarisiz: {e}")
            return None

    def restore(self, backup_path: Path) -> bool:
        """Yedekten geri yukle"""
        if not backup_path.exists():
            log_error(f"Yedek dosyasi bulunamadi: {backup_path}")
            return False

        log_info(f"Geri yukleme yapiliyor: {backup_path}")

        try:
            import tarfile
            with tarfile.open(backup_path, 'r:gz') as tar:
                tar.extractall(SCRIPT_DIR)

            log_success("Geri yukleme tamamlandi")
            return True

        except Exception as e:
            log_error(f"Geri yukleme basarisiz: {e}")
            return False

    def reset(self) -> bool:
        """Veritabanini sifirla"""
        if self.db_path.exists():
            log_warning("Mevcut veritabani siliniyor...")
            self.db_path.unlink()

        log_success("Veritabani sifirlandi. Yeniden baslatinca olusturulacak.")
        return True

    def get_stats(self) -> Dict:
        """Veritabani istatistiklerini al"""
        if not self.db_path.exists():
            return {'exists': False}

        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            stats = {'exists': True}

            # Rapor sayisi
            cursor.execute("SELECT COUNT(*) FROM reports")
            stats['reports'] = cursor.fetchone()[0]

            # Bulgu sayisi
            cursor.execute("SELECT COUNT(*) FROM findings")
            stats['findings'] = cursor.fetchone()[0]

            # Kullanici sayisi
            cursor.execute("SELECT COUNT(*) FROM users")
            stats['users'] = cursor.fetchone()[0]

            # Kural sayisi
            cursor.execute("SELECT COUNT(*) FROM security_rules")
            stats['rules'] = cursor.fetchone()[0]

            conn.close()
            return stats

        except Exception as e:
            return {'exists': True, 'error': str(e)}

# ============================================
# Installer Sinifi
# ============================================

class Installer:
    """Ana kurulum sinifi"""

    def __init__(self):
        self.checker = SystemChecker()
        self.deps = DependencyManager(self.checker)
        self.services = ServiceManager()
        self.db = DatabaseManager()

    def run_full_install(self) -> bool:
        """Tam kurulum"""
        log_info("Tam kurulum basliyor...")

        # Sistem kontrolu
        results = self.checker.check_all()
        self.checker.display_results(results)

        # Kritik bagimliliklari kontrol et
        if not results['python']['status']:
            log_error("Python 3.8+ gerekli!")
            return False

        if not results['node']['status']:
            log_error("Node.js 18+ gerekli!")
            return False

        # Dizinleri olustur
        self._create_directories()

        # Backend kurulumu
        if not self._install_backend():
            return False

        # Frontend kurulumu
        if not self._install_frontend():
            return False

        # APKTool kurulumu
        if not results['apktool']['status']:
            if RICH_AVAILABLE:
                if Confirm.ask("APKTool kurulsun mu?", default=True):
                    self.deps.install_apktool()
            else:
                self.deps.install_apktool()

        # Konfigürasyon
        self._create_env_file()

        # Tamamlandi
        self._show_completion_message()
        return True

    def _create_directories(self):
        """Gerekli dizinleri olustur"""
        log_info("Dizinler olusturuluyor...")
        for dir_path in [DATA_DIR, UPLOADS_DIR, LOGS_DIR, CONFIG_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)
        log_success("Dizinler olusturuldu")

    def _install_backend(self) -> bool:
        """Backend kurulumu"""
        log_info("Backend kuruluyor...")

        venv_path = BACKEND_DIR / 'venv'

        # Virtual environment olustur
        if not venv_path.exists():
            log_info("Virtual environment olusturuluyor...")
            run_command([get_python_cmd(), '-m', 'venv', str(venv_path)])

        # Bagimliliklari kur
        requirements = BACKEND_DIR / 'requirements.txt'
        if requirements.exists():
            if not self.deps.install_python_deps(venv_path, requirements):
                return False

        log_success("Backend kuruldu")
        return True

    def _install_frontend(self) -> bool:
        """Frontend kurulumu"""
        log_info("Frontend kuruluyor...")

        if not self.deps.install_node_deps(FRONTEND_DIR):
            return False

        log_success("Frontend kuruldu")
        return True

    def _create_env_file(self):
        """Environment dosyasi olustur"""
        env_file = SCRIPT_DIR / '.env'
        if env_file.exists():
            log_warning(".env dosyasi zaten mevcut, atlanıyor")
            return

        log_info(".env dosyasi olusturuluyor...")

        # JWT secret key olustur
        jwt_secret = secrets.token_hex(32)

        content = f"""# MobAI Environment Configuration
# Olusturulma: {datetime.now().isoformat()}

# Database
DATABASE_PATH={DATA_DIR}/mobile_analyzer.db

# Directories
UPLOAD_DIR={UPLOADS_DIR}
DATA_DIR={DATA_DIR}

# Authentication
JWT_SECRET_KEY={jwt_secret}
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# CORS (comma-separated)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Optional: NVD API Key for CVE matching
# NVD_API_KEY=your-api-key-here

# Optional: AI Provider (configured via web UI)
# AI_PROVIDER=openai
# AI_API_KEY=your-api-key-here
"""
        env_file.write_text(content)
        log_success(".env dosyasi olusturuldu")

    def _show_completion_message(self):
        """Tamamlanma mesaji goster"""
        if RICH_AVAILABLE:
            message = f"""
[bold green]Kurulum Basariyla Tamamlandi![/bold green]

[cyan]Backend:[/cyan]  http://localhost:{DEFAULT_BACKEND_PORT}
[cyan]Frontend:[/cyan] http://localhost:{DEFAULT_FRONTEND_PORT}
[cyan]API Docs:[/cyan] http://localhost:{DEFAULT_BACKEND_PORT}/api/docs

[yellow]Baslatmak icin:[/yellow] ./mobai start
[yellow]Durdurmak icin:[/yellow] ./mobai stop
[yellow]Durum icin:[/yellow]     ./mobai status
[yellow]Yardim icin:[/yellow]    ./mobai --help
"""
            console.print(Panel(message, title="MobAI", border_style="green"))
        else:
            print("\n" + "="*50)
            print("  Kurulum Basariyla Tamamlandi!")
            print("="*50)
            print(f"\n  Backend:  http://localhost:{DEFAULT_BACKEND_PORT}")
            print(f"  Frontend: http://localhost:{DEFAULT_FRONTEND_PORT}")
            print(f"  API Docs: http://localhost:{DEFAULT_BACKEND_PORT}/api/docs")
            print("\n  Baslatmak icin: ./mobai start")
            print("  Durdurmak icin: ./mobai stop")
            print("="*50 + "\n")

    def install_optional_tools(self):
        """Opsiyonel araclari kur"""
        if not RICH_AVAILABLE:
            log_warning("Interaktif mod icin rich gerekli")
            return

        tools = [
            {'name': 'Frida Tools', 'id': 'frida', 'desc': 'DAST icin dinamik analiz araci'},
            {'name': 'ADB', 'id': 'adb', 'desc': 'Android cihaz baglantisi'},
            {'name': 'Jadx', 'id': 'jadx', 'desc': 'Java decompiler'},
            {'name': 'Objection', 'id': 'objection', 'desc': 'Frida wrapper - otomatik bypass'},
            {'name': 'Radare2', 'id': 'r2', 'desc': 'Binary analiz araci'},
        ]

        choices = questionary.checkbox(
            "Hangi araclari kurmak istiyorsunuz?",
            choices=[questionary.Choice(f"{t['name']} - {t['desc']}", value=t['id']) for t in tools],
            style=CUSTOM_STYLE
        ).ask()

        if not choices:
            log_info("Hicbir arac secilmedi")
            return

        for tool_id in choices:
            self._install_tool(tool_id)

    def _install_tool(self, tool_id: str):
        """Belirli bir araci kur"""
        log_info(f"{tool_id} kuruluyor...")

        if tool_id == 'frida':
            run_command(['pip', 'install', 'frida-tools'])
        elif tool_id == 'adb':
            pm = self.checker.os_info['package_manager']
            if pm == 'apt':
                self.deps.install_system_packages(['android-tools-adb'])
            elif pm == 'brew':
                self.deps.install_system_packages(['android-platform-tools'])
            elif pm == 'pacman':
                self.deps.install_system_packages(['android-tools'])
        elif tool_id == 'jadx':
            # Jadx kurulumu
            log_warning("Jadx manuel kurulum gerektirir: https://github.com/skylot/jadx")
        elif tool_id == 'objection':
            run_command(['pip', 'install', 'objection'])
        elif tool_id == 'r2':
            pm = self.checker.os_info['package_manager']
            if pm in ['apt', 'dnf', 'pacman']:
                self.deps.install_system_packages(['radare2'])
            elif pm == 'brew':
                self.deps.install_system_packages(['radare2'])

        log_success(f"{tool_id} kuruldu")

# ============================================
# CLI Komutlari
# ============================================

if RICH_AVAILABLE:
    @click.group(invoke_without_command=True)
    @click.option('--version', '-v', is_flag=True, help='Versiyon goster')
    @click.pass_context
    def cli(ctx, version):
        """MobAI - Mobile Security Analyzer Kurulum ve Yonetim Araci"""
        if version:
            console.print(f"MobAI v{VERSION}")
            return

        if ctx.invoked_subcommand is None:
            print_banner()
            show_main_menu()

    @cli.command()
    @click.option('--full', is_flag=True, help='Tam kurulum (interaktif sormadan)')
    @click.option('--backend', is_flag=True, help='Sadece backend kur')
    @click.option('--frontend', is_flag=True, help='Sadece frontend kur')
    @click.option('--docker', is_flag=True, help='Docker ile kur')
    @click.option('--dev', is_flag=True, help='Gelistirici modu')
    def install(full, backend, frontend, docker, dev):
        """Kurulum yap"""
        installer = Installer()

        if docker:
            log_info("Docker kurulumu basliyor...")
            code, _, _ = run_command(['docker-compose', 'up', '-d', '--build'], cwd=SCRIPT_DIR)
            if code == 0:
                log_success("Docker kurulumu tamamlandi")
            else:
                log_error("Docker kurulumu basarisiz")
            return

        if backend:
            installer._install_backend()
            return

        if frontend:
            installer._install_frontend()
            return

        installer.run_full_install()

    @cli.command()
    def start():
        """Servisleri baslat"""
        services = ServiceManager()
        services.start_all()
        services.display_status()

    @cli.command()
    def stop():
        """Servisleri durdur"""
        services = ServiceManager()
        services.stop_all()

    @cli.command()
    def restart():
        """Servisleri yeniden baslat"""
        services = ServiceManager()
        services.restart_all()
        services.display_status()

    @cli.command()
    def status():
        """Servis durumunu goster"""
        services = ServiceManager()
        services.display_status()

    @cli.command()
    @click.option('--follow', '-f', is_flag=True, help='Canli log takibi')
    def logs(follow):
        """Loglari goster"""
        log_file = LOGS_DIR / 'mobai.log'
        if not log_file.exists():
            log_warning("Log dosyasi bulunamadi")
            return

        if follow:
            run_command(['tail', '-f', str(log_file)], capture=False)
        else:
            run_command(['tail', '-n', '50', str(log_file)], capture=False)

    @cli.command()
    def health():
        """Sistem saglik kontrolu"""
        print_banner()
        checker = SystemChecker()
        results = checker.check_all()
        checker.display_results(results)

        # Servis durumu
        services = ServiceManager()
        services.display_status()

        # Veritabani
        db = DatabaseManager()
        stats = db.get_stats()
        if stats.get('exists'):
            console.print(f"\n[cyan]Veritabani:[/cyan] {stats.get('reports', 0)} rapor, {stats.get('findings', 0)} bulgu")

    @cli.command()
    def check():
        """Sistem gereksinimlerini kontrol et"""
        checker = SystemChecker()
        results = checker.check_all()
        checker.display_results(results)

    @cli.command()
    def update():
        """Uygulamayi guncelle"""
        log_info("Guncelleme basliyor...")

        # Git pull
        code, out, err = run_command(['git', 'pull'], cwd=SCRIPT_DIR)
        if code == 0:
            log_success("Kod guncellendi")
        else:
            log_warning("Git pull basarisiz, devam ediliyor...")

        # Backend bagimliliklari
        installer = Installer()
        installer._install_backend()
        installer._install_frontend()

        log_success("Guncelleme tamamlandi")

    @cli.command()
    def uninstall():
        """Uygulamayi kaldir"""
        if not Confirm.ask("[red]Uygulamayi kaldirmak istediginize emin misiniz?[/red]", default=False):
            return

        # Servisleri durdur
        services = ServiceManager()
        services.stop_all()

        # Yedek al
        if Confirm.ask("Veritabanini yedeklemek ister misiniz?", default=True):
            db = DatabaseManager()
            db.backup()

        # Dizinleri sil
        if Confirm.ask("Tum verileri silmek ister misiniz? (uploads, data)", default=False):
            shutil.rmtree(DATA_DIR, ignore_errors=True)
            shutil.rmtree(UPLOADS_DIR, ignore_errors=True)

        # Virtual environment sil
        shutil.rmtree(BACKEND_DIR / 'venv', ignore_errors=True)
        shutil.rmtree(FRONTEND_DIR / 'node_modules', ignore_errors=True)

        log_success("Kaldirma tamamlandi")

    @cli.group()
    def db():
        """Veritabani islemleri"""
        pass

    @db.command('init')
    def db_init():
        """Veritabanini baslat"""
        log_info("Veritabani baslatilacak (backend baslatildiginda otomatik olusur)")

    @db.command('reset')
    def db_reset():
        """Veritabanini sifirla"""
        if Confirm.ask("[red]Veritabanini sifirlamak istediginize emin misiniz?[/red]", default=False):
            db = DatabaseManager()
            db.reset()

    @db.command('backup')
    def db_backup():
        """Veritabanini yedekle"""
        db = DatabaseManager()
        db.backup()

    @db.command('restore')
    @click.argument('file', type=click.Path(exists=True))
    def db_restore(file):
        """Yedekten geri yukle"""
        db = DatabaseManager()
        db.restore(Path(file))

    @cli.group()
    def tools():
        """Opsiyonel arac islemleri"""
        pass

    @tools.command('install')
    def tools_install():
        """Opsiyonel araclari kur"""
        installer = Installer()
        installer.install_optional_tools()

    @tools.command('list')
    def tools_list():
        """Kurulu araclari listele"""
        tools_to_check = ['frida', 'adb', 'jadx', 'objection', 'r2']
        console.print("\n[cyan]Kurulu Araclar:[/cyan]")
        for tool in tools_to_check:
            if check_command(tool):
                console.print(f"  [green]✓[/green] {tool}")
            else:
                console.print(f"  [red]✗[/red] {tool}")

    def show_main_menu():
        """Ana menu goster"""
        choices = [
            '1. Tam Kurulum (Onerilen)',
            '2. Docker Kurulumu',
            '3. Sadece Backend',
            '4. Sadece Frontend',
            '5. Gelistirici Modu',
            '6. Guncelleme',
            '7. Sistem Kontrolu',
            '8. Servis Yonetimi',
            '9. Veritabani Yonetimi',
            '10. Opsiyonel Araclar',
            '0. Cikis'
        ]

        choice = questionary.select(
            "Ne yapmak istiyorsunuz?",
            choices=choices,
            style=CUSTOM_STYLE
        ).ask()

        if not choice:
            return

        idx = int(choice.split('.')[0])

        installer = Installer()

        if idx == 1:
            installer.run_full_install()
        elif idx == 2:
            run_command(['docker-compose', 'up', '-d', '--build'], cwd=SCRIPT_DIR)
        elif idx == 3:
            installer._install_backend()
        elif idx == 4:
            installer._install_frontend()
        elif idx == 5:
            installer.run_full_install()
            installer.services.start_all()
        elif idx == 6:
            ctx = click.Context(update)
            ctx.invoke(update)
        elif idx == 7:
            ctx = click.Context(health)
            ctx.invoke(health)
        elif idx == 8:
            show_service_menu()
        elif idx == 9:
            show_db_menu()
        elif idx == 10:
            installer.install_optional_tools()
        elif idx == 0:
            console.print("[yellow]Gule gule![/yellow]")
            sys.exit(0)

    def show_service_menu():
        """Servis yonetim menusu"""
        services = ServiceManager()

        choices = [
            '1. Servisleri Baslat',
            '2. Servisleri Durdur',
            '3. Yeniden Baslat',
            '4. Durum Goster',
            '0. Geri'
        ]

        choice = questionary.select(
            "Servis islemleri:",
            choices=choices,
            style=CUSTOM_STYLE
        ).ask()

        if not choice:
            return

        idx = int(choice.split('.')[0])

        if idx == 1:
            services.start_all()
            services.display_status()
        elif idx == 2:
            services.stop_all()
        elif idx == 3:
            services.restart_all()
            services.display_status()
        elif idx == 4:
            services.display_status()

    def show_db_menu():
        """Veritabani yonetim menusu"""
        db = DatabaseManager()

        choices = [
            '1. Yedekle',
            '2. Geri Yukle',
            '3. Sifirla',
            '4. Istatistikler',
            '0. Geri'
        ]

        choice = questionary.select(
            "Veritabani islemleri:",
            choices=choices,
            style=CUSTOM_STYLE
        ).ask()

        if not choice:
            return

        idx = int(choice.split('.')[0])

        if idx == 1:
            db.backup()
        elif idx == 2:
            file_path = Prompt.ask("Yedek dosyasi yolu")
            db.restore(Path(file_path))
        elif idx == 3:
            if Confirm.ask("[red]Emin misiniz?[/red]", default=False):
                db.reset()
        elif idx == 4:
            stats = db.get_stats()
            if stats.get('exists'):
                console.print(f"Raporlar: {stats.get('reports', 0)}")
                console.print(f"Bulgular: {stats.get('findings', 0)}")
                console.print(f"Kullanicilar: {stats.get('users', 0)}")
                console.print(f"Kurallar: {stats.get('rules', 0)}")
            else:
                console.print("[yellow]Veritabani bulunamadi[/yellow]")

else:
    # Rich olmadan basit CLI
    def show_help():
        print_banner()
        print("Kullanim: ./mobai <komut> [secenekler]")
        print("\nKomutlar:")
        print("  install     - Kurulum yap")
        print("  start       - Servisleri baslat")
        print("  stop        - Servisleri durdur")
        print("  restart     - Servisleri yeniden baslat")
        print("  status      - Durum goster")
        print("  health      - Sistem kontrolu")
        print("  check       - Sistem gereksinimlerini kontrol et")
        print("  update      - Uygulamayi guncelle")
        print("  uninstall   - Uygulamayi kaldir")
        print("  db backup   - Veritabani yedekle")
        print("  db restore  - Veritabani geri yukle")
        print("  db reset    - Veritabani sifirla")
        print("  tools list  - Opsiyonel araclari listele")
        print("  tools install - Opsiyonel arac kur")
        print("\nSecenekler:")
        print("  --help, -h     Yardim goster")
        print("  --version, -v  Versiyon goster")
        print("\nOrnekler:")
        print("  ./mobai install          # Interaktif kurulum")
        print("  ./mobai start            # Servisleri baslat")
        print("  ./mobai status           # Durum kontrolu")
        print("  ./mobai db backup        # Veritabani yedekle")

    def cli():
        if len(sys.argv) < 2:
            show_help()
            return

        cmd = sys.argv[1]

        # Yardim ve versiyon
        if cmd in ['--help', '-h', 'help']:
            show_help()
            return
        if cmd in ['--version', '-v', 'version']:
            print(f"MobAI v{VERSION}")
            return

        installer = Installer()
        services = ServiceManager()
        db = DatabaseManager()

        if cmd == 'install':
            installer.run_full_install()
        elif cmd == 'start':
            services.start_all()
            services.display_status()
        elif cmd == 'stop':
            services.stop_all()
        elif cmd == 'restart':
            services.restart_all()
            services.display_status()
        elif cmd == 'status':
            services.display_status()
        elif cmd == 'health':
            print_banner()
            checker = SystemChecker()
            results = checker.check_all()
            checker.display_results(results)
            services.display_status()
        elif cmd == 'check':
            checker = SystemChecker()
            results = checker.check_all()
            checker.display_results(results)
        elif cmd == 'update':
            log_info("Guncelleme basliyor...")
            code, _, _ = run_command(['git', 'pull'], cwd=SCRIPT_DIR)
            if code == 0:
                log_success("Kod guncellendi")
            installer._install_backend()
            installer._install_frontend()
            log_success("Guncelleme tamamlandi")
        elif cmd == 'uninstall':
            confirm = input("Uygulamayi kaldirmak istediginize emin misiniz? (e/h): ")
            if confirm.lower() == 'e':
                services.stop_all()
                shutil.rmtree(BACKEND_DIR / 'venv', ignore_errors=True)
                shutil.rmtree(FRONTEND_DIR / 'node_modules', ignore_errors=True)
                log_success("Kaldirma tamamlandi")
        elif cmd == 'db':
            if len(sys.argv) < 3:
                print("Kullanim: ./mobai db <backup|restore|reset>")
                return
            subcmd = sys.argv[2]
            if subcmd == 'backup':
                db.backup()
            elif subcmd == 'restore':
                if len(sys.argv) < 4:
                    print("Kullanim: ./mobai db restore <dosya>")
                    return
                db.restore(Path(sys.argv[3]))
            elif subcmd == 'reset':
                confirm = input("Veritabanini sifirlamak istediginize emin misiniz? (e/h): ")
                if confirm.lower() == 'e':
                    db.reset()
            else:
                print(f"Bilinmeyen db komutu: {subcmd}")
        elif cmd == 'tools':
            if len(sys.argv) < 3:
                print("Kullanim: ./mobai tools <list|install>")
                return
            subcmd = sys.argv[2]
            if subcmd == 'list':
                print("\nOpsiyonel Araclar:")
                print("  frida     - Frida araclari")
                print("  adb       - Android Debug Bridge")
                print("  jadx      - Java decompiler")
                print("  objection - Frida tabanlı güvenlik araci")
                print("  r2        - Radare2 reverse engineering")
            elif subcmd == 'install':
                if len(sys.argv) < 4:
                    print("Kullanim: ./mobai tools install <arac>")
                    return
                installer._install_tool(sys.argv[3])
            else:
                print(f"Bilinmeyen tools komutu: {subcmd}")
        else:
            print(f"Bilinmeyen komut: {cmd}")
            print("Yardim icin: ./mobai --help")

# ============================================
# Ana Giris
# ============================================

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        print("\n")
        log_warning("Iptal edildi")
        sys.exit(130)
    except Exception as e:
        log_error(f"Beklenmeyen hata: {e}")
        sys.exit(1)
