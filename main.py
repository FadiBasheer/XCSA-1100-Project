import nmap

def scan_for_vulnerabilities(target_ip):
    nm = nmap.PortScanner()

    print(f"Scanning {target_ip} for vulnerabilities...")

     #Perform a vulnerability scan using Nmap
    #temp=nm.scan(target_ip, arguments='-sV -O --script vulners')

    temp=nm.scan(target_ip, arguments='-sV -O -PE')
    # Print the scan results
    print(f"Scanning target: {target_ip}")

    #print(temp)
    print(f"Host status is: {temp['scan'][target_ip]['status']['state']}")
    print(f"OS Name: {temp['scan'][target_ip]['osmatch'][0]['name']}")
    # Print the scanned ports and their service/version information
    for port, info in temp['scan'][target_ip]['tcp'].items():
        print(f"Port {port}: {info['name']} - {info['product']} {info['version']}")

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")

    scan_for_vulnerabilities(target_ip)



# to find range of IPs
#nmap -sN -PE 192.168.84.129-140