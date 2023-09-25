#import nmap
#
#def scan_for_vulnerabilities(target_ip):
#    nm = nmap.PortScanner()
#
#    print(f"Scanning {target_ip} for vulnerabilities...")
#
#     #Perform a vulnerability scan using Nmap
#    #temp=nm.scan(target_ip, arguments='-sV -O --script vulners')
#
#    temp=nm.scan(target_ip, arguments='-sV -O -PE')
#    # Print the scan results
#    print(f"Scanning target: {target_ip}")
#
#    #print(temp)
#    print(f"Host status is: {temp['scan'][target_ip]['status']['state']}")
#    print(f"OS Name: {temp['scan'][target_ip]['osmatch'][0]['name']}")
#    # Print the scanned ports and their service/version information
#    for port, info in temp['scan'][target_ip]['tcp'].items():
#        print(f"Port {port}: {info['name']} - {info['product']} {info['version']}")
#
#if __name__ == "__main__":
#    target_ip = input("Enter the target IP address: ")
#
#    scan_for_vulnerabilities(target_ip)



# to find range of IPs
#nmap -sN -PE 192.168.84.129-140

import nmap

def scan_for_vulnerabilities(target_ip):
    nm = nmap.PortScanner()

    # Perform the Nmap scan
    temp = nm.scan(target_ip, arguments='-sV -O -PE')

    # Iterate over the hosts and print information
    for target_ip, scan_result in temp['scan'].items():
        print(f"Results for {target_ip}:")
        print(f"Host is up: {scan_result['status']['state']}")
        
        if 'osclass' in scan_result:
            print("Operating System Information:")
            for os_info in scan_result['osclass']:
                print(f"  - OS Family: {os_info['osfamily']}")
                print(f"  - OS Gen: {os_info['osgen']}")
                print(f"  - OS Accuracy: {os_info['accuracy']}")
                # Add more OS information fields if needed
        
        if 'tcp' in scan_result:
            print("Open Ports:")
            for port, port_info in scan_result['tcp'].items():
                print(f"  - Port {port}: {port_info['name']} - {port_info['product']} - {port_info['version']}")

        # Add more information as needed

        print("="*50)  # Separator between hosts
        
if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")

    scan_for_vulnerabilities(target_ip)



