# Sub_Scanner

Security Audit Tool
This is a Python script that performs a basic security audit on a target domain. The script gathers information about the target domain, including subdomains, technical information, open ports, and potential vulnerabilities.

Features
Subdomain discovery: Uses the sublist3r library to discover subdomains of the target domain.
Technical information: Retrieves the IP address of the target domain using the socket library.
Port scanning: Uses the nmap library to scan the target domain for open ports in the range of 1-1024.
Vulnerability scanning: Currently a placeholder, but can be replaced with actual vulnerability scanning tools and techniques.
Usage
Clone the repository and install the required libraries by running pip install -r requirements.txt.
Run the script by executing python security_audit.py.
Enter the target domain when prompted.
The script will perform the security audit and save the results to a file named security_audit_results.txt.
Output
The script will output the results of the security audit to a file named security_audit_results.txt. The file will contain the following information:

Subdomains of the target domain
Technical information about the target domain (IP address)
Open ports on the target domain
Potential vulnerabilities (currently a placeholder)
Requirements
Python 3.x
sublist3r library
nmap library
socket library
License
This script is licensed under the MIT License. You are free to use, modify, and distribute this script as per the terms of the license.

Contributing
If you'd like to contribute to this project, please fork the repository and submit a pull request with your changes. You can also report any issues or suggest new features by opening an issue.

Disclaimer
This script is for educational purposes only and should not be used to scan or exploit systems without permission. Always ensure you have the necessary permissions and follow applicable laws and regulations when performing security audits.
