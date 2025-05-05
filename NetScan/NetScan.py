from flask import Flask, render_template, request
import nmap
import socket

app = Flask(__name__)

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    def scan(self, ip_address, start_port=1, end_port=1024, ports="", arguments=""):
        try:
            # Build a combined list of ports from the range and individual ports
            range_ports = list(range(start_port, end_port + 1))
            individual_ports = []
            if ports.strip():
                individual_ports = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
            # Merge and sort the ports (removing duplicates)
            all_ports = sorted(set(range_ports + individual_ports))
            # Convert list to a comma-separated string for Nmap
            port_range = ",".join(str(p) for p in all_ports)
            print(f"Scanning {ip_address} on ports {port_range} with arguments:{arguments}")
            self.nm.scan(ip_address, port_range, arguments)
            return True
        except Exception as e:
            print("Scan ERROR:", e)
            return False

    def check_open_ports(self, ip_address, start_port=1, end_port=1024, ports="", arguments=""):
        if not self.scan(ip_address, start_port, end_port, ports, arguments):
            return None
        results = []
        for proto in ['tcp', 'udp']:
            try:
                # Optionally get host details
                host = socket.gethostbyaddr(ip_address)
            except Exception:
                host = None
            # Build the combined list of ports again for iterating over results
            range_ports = list(range(start_port, end_port + 1))
            individual_ports = []
            if ports.strip():
                individual_ports = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
            ports_to_scan = sorted(set(range_ports + individual_ports))
            for port in ports_to_scan:
                try:
                    port_info = self.nm[ip_address][proto].get(port)
                    if port_info and port_info.get('state') == 'open':
                        results.append({"IP": ip_address, "Port": port, "Protocol": proto})
                except Exception:
                    continue
        return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip_address = request.form.get('ip_address')
    start_port = request.form.get('start_port') or "1"
    end_port = request.form.get('end_port') or "1024"
    ports = request.form.get('ports') or ""
    try:
        start_port = int(start_port)
        end_port = int(end_port)
    except ValueError:
        return render_template('index.html', error="Please enter valid port numbers.")

    options = []
    # Basic Scanning Options
    if request.form.get('stealth'):
        options.append(" -sS")
    if request.form.get('udp'):
        options.append(" -sU")
    if request.form.get('service'):
        options.append(" -sV")
    if request.form.get('os'):
        options.append(" -O")
    # Network Discovery Options
    if request.form.get('ping_sweep'):
        options.append(" -sn")
    if request.form.get('arp'):
        options.append(" -PR")
    # Packet Options
    if request.form.get('fragment'):
        options.append(" -f")
    if request.form.get('randomize'):
        options.append(" --randomize-ports")
    # Timing Options
    if request.form.get('timing_slow'):
        options.append(" -T0")
    if request.form.get('timing_fast'):
        options.append(" -T4")
    # Additional Scans and Scripts
    if request.form.get('common_vuln'):
        options.append(" -sC")
    if request.form.get('firewall'):
        options.append(" -sA")
    if request.form.get('traceroute'):
        options.append(" --traceroute")
    if request.form.get('ftp_brute'):
        options.append(" --script ftp-brute")
    if request.form.get('vuln_scan'):
        options.append(" --script vuln")

    arguments = "".join(options)
    
    scanner = NetworkScanner()
    results = scanner.check_open_ports(ip_address, start_port, end_port, ports, arguments)
    return render_template('index.html', results=results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)