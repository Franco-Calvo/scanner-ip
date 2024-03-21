import nmap

def scan_range(start, end, ports):
    """
    Escanea un rango específico de direcciones IP.
    """
    scanner = nmap.PortScanner()
    ip_range = f"192.168.0.{start}-{end}"
    print(f"Iniciando escaneo del rango {ip_range} en los puertos {ports}")
    scanner.scan(hosts=ip_range, ports=ports, arguments='-sV')
    
    for host in scanner.all_hosts():
        if 'hostnames' in scanner[host] and scanner[host]['hostnames']:
            hostname = scanner[host]['hostnames'][0]['name']
        else:
            hostname = "Desconocido"
        
        print(f"IP: {host}, Hostname: {hostname}")

for i in range(0, 255, 10): 
    scan_range(i, min(i+9, 254), "80,443")  
