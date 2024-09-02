import psutil
from datetime import datetime

class PortScanner:
    def scan_open_ports(self):
        open_ports = []
        for connection in psutil.net_connections(kind='inet'):
            if connection.status == psutil.CONN_LISTEN:
                open_ports.append((connection.laddr.port, connection.pid))
        return open_ports

class ProcessChecker:
    SUSPICIOUS_PROCESS_NAMES = ["malware", "hacktool", "unknown"]

    def check_process(self, pid):
        try:
            process = psutil.Process(pid)
            if self.is_suspicious(process):
                self.report_suspicious_process(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            print(f"Prozess mit PID {pid} konnte nicht überprüft werden.")

    def is_suspicious(self, process):
        return (self._is_name_suspicious(process) or
                self._is_cpu_usage_high(process) or
                self._is_memory_usage_high(process))

    def _is_name_suspicious(self, process):
        process_name = process.name().lower()
        return any(susp in process_name for susp in self.SUSPICIOUS_PROCESS_NAMES)

    def _is_cpu_usage_high(self, process):
        return process.cpu_percent(interval=1) > 80

    def _is_memory_usage_high(self, process):
        return process.memory_percent() > 50

    def report_suspicious_process(self, process):
        print(f"Warnung: Verdächtiger Prozess erkannt! PID: {process.pid}, Name: {process.name()}")
        print(f"Zusätzliche Informationen: {process.cmdline()}")

class NetworkMonitor:
    def check_network_activity(self):
        net_io = psutil.net_io_counters()
        print(f"Gesendete Bytes: {net_io.bytes_sent}")
        print(f"Empfangene Bytes: {net_io.bytes_recv}")

class ProcessMonitor:
    def __init__(self, process_checker):
        self.process_checker = process_checker

    def check_running_processes(self):
        for process in psutil.process_iter(['pid', 'name', 'username']):
            try:
                print(f"Prozess: {process.info['name']} | PID: {process.info['pid']} | Benutzer: {process.info['username']}")
                self.process_checker.check_process(process.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

class MonitoringProgram:
    def __init__(self):
        self.port_scanner = PortScanner()
        self.process_checker = ProcessChecker()
        self.network_monitor = NetworkMonitor()
        self.process_monitor = ProcessMonitor(self.process_checker)

    def run(self):
        print(f"Überwachungsprogramm gestartet: {datetime.now()}")
        
        self.scan_and_check_ports()
        self.network_monitor.check_network_activity()
        self.process_monitor.check_running_processes()

        print(f"Überwachungsprogramm abgeschlossen: {datetime.now()}")

    def scan_and_check_ports(self):
        open_ports = self.port_scanner.scan_open_ports()
        if open_ports:
            print("Offene Ports gefunden:")
            for port, pid in open_ports:
                process_name = psutil.Process(pid).name() if pid else "unbekannt"
                print(f"Port: {port}, ProzessID: {pid}, Prozessname: {process_name}")
                self.process_checker.check_process(pid)
        else:
            print("Keine offenen Ports gefunden.")

if __name__ == "__main__":
    monitoring_program = MonitoringProgram()
    monitoring_program.run()
