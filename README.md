# Automating Penetration Tool

## Description
This application automates most of the penetration testing tasks using the command line. It automates information gathering of DNS, Emails, WHOIS, Files, social media (Using Google Dorking), Scans for live hosts, Port scanning, Vulnerability assessment as per OWASP standard, Brute-force attack, Scans for Web site security as well.

This application can be used only on "Kali Linux", it will not work on other Linux versions unless you install all the required tools manually.


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
