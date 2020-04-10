![apt-logo](resources/Logo.png?raw=true "Apt-logo")

# Summary
This application automates most of the penetration testing tasks using the command line. It automates information gathering of DNS, e-mails, WHOIS, files, social media (Using Google Dorking), scans for live hosts, port scanning, vulnerability assessment as per OWASP standards, brute-force attacks, and scans for Website security as well.

This application can be used only on "Kali Linux", it will not work on other Linux versions unless you install all the required tools manually.

# How it works
APT uses Python to create an automated framework to use industry standard tools (such as preinstalled kali tools, OWASP ZAP and Nmap etc) to perform repeatable, well-designed procedures with anticipated results to create an easily understandable report listing vulnerabilities detected within the web application.

## Information Gathering
  ```DNS
  To get information about a dns:
  $python apt.py --company [YourClientDomainName] -dns
  ```
  
   ```Emails
  To get a list of email addresses:
  $python apt.py --company [YourClientDomainName] -emails
  ```
  
   ```WHOIS
  To get information about WHOIS:
  $python apt.py --company [YourClientDomainName] -whois
  ```
  
   ```Files
  To get a list of leaked files on the internet:
  $python apt.py --company [YourClientDomainName] -files
  ```
  
   ```SocialMedia
  To get information about your client social media:
  $python apt.py --company [YourClientDomainName] -socialmedia
  ```
  
   ```WebSearch
  To get information about your client using the search engines:
  $python apt.py --company [YourClientDomainName] -websearch
  ```
  
## Scanning
   ```LiveHosts
  To scan for live hosts:
  $python apt.py --company [YourClientDomainName] -ip [NetworkIPAddress/Range] -livehosts
  ```
  
   ```PortScan
  For Port Scanning:
  $python apt.py --company [YourClientDomainName] -ip [NetworkIPAddress/Range] -portscan
  ```
  
## Vulnerability Assessment
   ```VulnsScan
  Vulnerability Scan:
  $python apt.py --company [YourClientDomainName] -ip [NetworkIPAddress/Range] -vulns
  ```
  
   ```BruteForce
  To brute-force the services on the client host machine(s):
  $python apt.py --company [YourClientDomainName] -ip [NetworkIPAddress/Range] -bruteforce
  ```
## Web Application Scan  
   ```WAF
  To get information about the existence of Web Application Firewall (WAF):
  $python apt.py --company [YourClientDomainName] --url [WebServerUrl] -waf
  ```
  
   ```SSL
  To get information about the server SSL/TLS security:
  $python apt.py --company [YourClientDomainName] --url [WebServerUrl] -ssl
  ```
  
   ```LoadBalance
  To get information about the webserver load balancing:
  $python apt.py --company [YourClientDomainName] --url [WebServerUrl] -loadbalance
  ```
  
  ```WebVulns
  Web Server Vulnerability Assessment:
  $python apt.py --company [YourClientDomainName] --url [WebServerUrl] -webvulns
  ```

  ```SQLMap
  To perform SQLMAP:
  $python apt.py --company [YourClientDomainName] --url [WebServerUrl] -sql
  ```
  ```OWASP Scanner using ADAPT
  Scan the whole web-application as per OWASP standards:
  $python apt.py --company [YourClientDomainName] -owasp
  ```

# Credits
This application uses Open Source components. You can find the source code of their open source projects along with license information below. We acknowledge and are grateful to these developers for their contributions to open source.
  
  Project: Adapt https://github.com/secdec/adapt
  Licensed under the Apache-2.0 License.
  
  Project: Kali Linux https://www.kali.org/
  © OffSec Services Limited 2020 All rights reserved

###### Author will not be held responsible for any illegal use of the tool. The tool should solely be used for educational purposes. 
