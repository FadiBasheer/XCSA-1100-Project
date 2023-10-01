import nmap


def calculate_vulnerability_score(scan_result):
    vulnerability_score = 0

    if 'tcp' in scan_result:
        vulnerability_score = len(scan_result['tcp'].items())

    return vulnerability_score


def find_most_vulnerable_server(scan_results):
    most_vulnerable_server = None
    highest_vulnerability_score = 0

    for target_ip, scan_result in scan_results.items():
        vulnerability_score = calculate_vulnerability_score(scan_result)

        if vulnerability_score > highest_vulnerability_score:
            highest_vulnerability_score = vulnerability_score
            most_vulnerable_server = target_ip

    return most_vulnerable_server, highest_vulnerability_score


def scan_for_vulnerabilities(target_ip):
    nm = nmap.PortScanner()

    # Perform the Nmap scan
    temp = nm.scan(target_ip, arguments='-sV -O -PE')

    # Iterate over the hosts and print information
    for target_ip, scan_result in temp['scan'].items():
        print(f"Results for {target_ip}:")
        print(f"Host is up: {scan_result['status']['state']}")

        if 'osmatch' in scan_result:
            print(
                f"Operating System Information: {scan_result['osmatch'][0]['name']}")

        if 'tcp' in scan_result:
            print("Open Ports:")
            for port, port_info in scan_result['tcp'].items():
                print(
                    f"  - Port {port}: {port_info['name']} - {port_info['product']} - {port_info['version']}")

        print("=" * 50)  # Separator between hosts

    # Find the most vulnerable server
    most_vulnerable_server, highest_vulnerability_score = find_most_vulnerable_server(
        temp['scan'])

    print(f"The most vulnerable server is: {most_vulnerable_server}")
    print(f"Highest Vulnerability Score: {highest_vulnerability_score}")


if __name__ == "__main__":
    print("Cisco model: {2}, {1} WAN slots, IOS {0}".format("2600XM", 2, 12.4))
    #target_ip = input("Enter the target IP address: ")

    #scan_for_vulnerabilities(target_ip)


# to find range of IPs
# nmap -sN -PE 192.168.84.129-140
#fsadfsf
