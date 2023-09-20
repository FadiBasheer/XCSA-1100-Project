#import nmap
#
#def scan_ip_range(start_ip, end_ip):
#    nm = nmap.PortScanner()
#
#    for i in range(int(start_ip.split('.')[-1]), int(end_ip.split('.')[-1]) + 1):
#        ip = start_ip.rsplit('.', 1)[0] + '.' + str(i)
#        print(f"Scanning {ip}...")
#
#        # Perform a basic Nmap scan on the target IP
#        nm.scan(ip, arguments='-sV --script vulners')
#
#        # Print the scan results
#        print(f"Scan results for {ip}:")
# #       print(nm[ip].csv())
#        print('Host : %s (%s)' % (ip, nm[ip].hostname()))
#
#
#        for proto in nm[ip].all_protocols():
#           print('----------')
#           print('Protocol : %s' % proto)
#           
#           lport = nm[ip][proto].keys()
#
#           print("lport: ",lport)
#           #lport.sort()
#           for port in lport:
#              print ('port : %s\tstate : %s' % (port, nm[ip][proto][port]['state']))
#
#if __name__ == "__main__":
#    start_ip = input("Enter the starting IP address: ")
#    end_ip = input("Enter the ending IP address: ")
#
#    scan_ip_range(start_ip, end_ip)


import nmap

def scan_for_vulnerabilities(target_ip):
    nm = nmap.PortScanner()

    print(f"Scanning {target_ip} for vulnerabilities...")

    # Perform a vulnerability scan using Nmap
    temp=nm.scan(target_ip, arguments='-sV --script vulners')

    # Print the scan results
    print(f"Scanning target: {target_ip}")
    print(f"Host is up: {temp['scan'][target_ip]['status']['state']}")

    # Print the scanned ports and their service/version information
    for port, info in temp['scan'][target_ip]['tcp'].items():
        print(f"Port {port}: {info['name']} - {info['product']} {info['version']}")

    # Print the vulnerabilities from the vulners NSE script
    print("Vulnerabilities:")
    if 'vulners' in temp['scan'][target_ip]:
        vulnerabilities = temp['scan'][target_ip]['vulners']
        for vuln in vulnerabilities:
            print(vuln)
    

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")

    scan_for_vulnerabilities(target_ip)
