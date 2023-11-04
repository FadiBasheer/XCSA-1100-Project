# Import the nmap library for network scanning
import nmap

# Define a function to calculate the vulnerability score for a given scan result
def calculate_vulnerability_score(scan_result):
    vulnerability_score = 0

    # Check if 'tcp' information is available in the scan result
    if 'tcp' in scan_result:
        # Calculate the vulnerability score as the number of open TCP ports
        vulnerability_score = len(scan_result['tcp'].items())

    return vulnerability_score

# Define a function to find the most vulnerable server from a dictionary of scan results
def find_most_vulnerable_server(scan_results):
    most_vulnerable_server = None
    highest_vulnerability_score = 0

    # Iterate over each target IP and its scan result
    for target_ip, scan_result in scan_results.items():
        # Calculate the vulnerability score for the current scan result
        vulnerability_score = calculate_vulnerability_score(scan_result)

        # Update the most vulnerable server if a higher vulnerability score is found
        if vulnerability_score > highest_vulnerability_score:
            highest_vulnerability_score = vulnerability_score
            most_vulnerable_server = target_ip

    return most_vulnerable_server, highest_vulnerability_score

# Define a function to perform network vulnerability scanning
def scan_for_vulnerabilities(target_ip):
    # Create an nmap PortScanner object
    nm = nmap.PortScanner()

    # Perform an Nmap scan on the target IP with specific scan arguments
    temp = nm.scan(target_ip, arguments='-sV -O -PE')

    # Iterate over the hosts in the scan result and print information
    for target_ip, scan_result in temp['scan'].items():
        print(f"Results for {target_ip}:")
        print(f"Host is up: {scan_result['status']['state']}")

        # Print the detected operating system information if available
        if 'osmatch' in scan_result:
            print(f"Operating System Information: {scan_result['osmatch'][0]['name']}")

        # Print information about open TCP ports if available
        if 'tcp' in scan_result:
            print("Open Ports:")
            for port, port_info in scan_result['tcp'].items():
                print(f"  - Port {port}: {port_info['name']} - {port_info['product']} - {port_info['version']}")

        print("=" * 50)  # Separator between hosts

    # Find the most vulnerable server among the scan results
    most_vulnerable_server, highest_vulnerability_score = find_most_vulnerable_server(
        temp['scan'])

    print(f"The most vulnerable server is: {most_vulnerable_server}")
    print(f"Highest Vulnerability Score: {highest_vulnerability_score}")

# Main entry point of the script
if __name__ == "__main__":
    # Prompt the user for the target IP address
    target_ip = input("Enter the target IP address: ")

    # Call the scan_for_vulnerabilities function with the user-provided target IP
    scan_for_vulnerabilities(target_ip)



# to find range of IPs
# nmap -sN -PE 192.168.84.129-140
#fsadfsfafasdfasf
