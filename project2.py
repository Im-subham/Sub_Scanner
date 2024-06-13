import subprocess
import socket
import nmap
import sublist3r

def get_subdomains(domain):
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains

def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')
    return nm[target]

def get_technical_info(target):
    try:
        ip_address = socket.gethostbyname(target)
        return {"IP Address": ip_address}
    except socket.error as e:
        return {"Error": str(e)}

def security_audit(target):
    # Placeholder for actual vulnerability scanning
    # Replace with appropriate security tools and techniques
    return {"vulnerabilities": "No vulnerabilities found (placeholder)."}

def main():
    target = input("Enter the target domain: ")
    print("Performing information gathering...")

    subdomains = get_subdomains(target)
    technical_info = get_technical_info(target)
    port_scan = scan_ports(target)
    vulnerabilities = security_audit(target)

    results = {
        "subdomains": subdomains,
        "technical_info": technical_info,
        "port_scan": port_scan,
        "vulnerabilities": vulnerabilities
    }

    # Saving results
    with open("security_audit_results.txt", "w") as file:
        for key, value in results.items():
            file.write(f"{key}:\n")
            if isinstance(value, dict):
                for k, v in value.items():
                    file.write(f"  {k}: {v}\n")
            else:
                for item in value:
                    file.write(f"  {item}\n")
            file.write("\n")

    print("Results saved to security_audit_results.txt")

if __name__ == "__main__":
    main()
