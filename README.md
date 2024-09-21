# SOC-Automation-Project

Generating an alert about mimikatz detection on a windows machine. The custom alert is received in wazuh and sent over to shuffle where it automates the process of checking the alert and then sending its SHA256 value over to VirusTotal. After receiving results it sends an email to SOC analyst for investigation. 
