# SOC AUTOMATION PROJECT

The Following diagram shows the general overview and flow of the project. 

![SOC AnalystModified (2)](https://github.com/user-attachments/assets/7268aae0-fb4a-4855-b56f-4839b9629d0c)

## SETTING UP WAZUH

We will send telemetry containing mimikatz to wazuh. The wazuh will
trigger mimikatz custom alert. We will be using windows 10 named DFIR with sysmon already installed. We need to make changes in the ossec file for log ingestion.

### Wazuh Installation

Install Wazuh 4.7 using the command

* curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
  
Extract Wazuh Credentials
* sudo tar -xvf wazuh-install-files.tar 

Checking status of indexer:

![image](https://github.com/user-attachments/assets/8717113a-f734-43cc-bbe4-6a3f4ecf18b3)

Checking status of dashboard:

![image](https://github.com/user-attachments/assets/e80361e6-48f5-4c0c-a6c8-b9901b46d964)

Checking status of manager:

![image](https://github.com/user-attachments/assets/323f1f34-ba54-4a07-8329-10eaf0c0b7c8)

Opening wazuh dashboard in browser after installting and checking the status of all componenets.

![image](https://github.com/user-attachments/assets/0f4cd0f1-df0c-46ce-a466-84223296ee4a)

Now we need to add an agent in wazuh dashboard. Adding agent windows 10 to the wazuh

![image](https://github.com/user-attachments/assets/35b27f87-56bd-4e42-b021-948a77609883)

On agent machine run the following command:

* Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile \${env.tmp}\wazuh-agent; msiexec.exe /i \${env.tmp}\wazuh-agent /q WAZUH_MANAGER=\'192.168.198.132\' WAZUH_AGENT_NAME=\'DFIR\' WAZUH_REGISTRATION_SERVER=\'192.168.198.132\'

![image](https://github.com/user-attachments/assets/b6a494d1-9616-4b2a-8093-3273e83f9e96)

![image](https://github.com/user-attachments/assets/eb05bcf7-fe2b-4459-bc30-77c88be359d6)

The agent is active in wazuh dashboard.

![image](https://github.com/user-attachments/assets/fc620bbd-bf97-4e69-97c9-1ef533ab74ee)

We have successfully configured wazuh. Our end goal is to detect mimikatz on our endpoint machine (windows 10), for that we will generate telemetry which in turn will generate an alert related to mimikatz.

### GENERATING TELEMETRY AND INGESTING LOGS IN WAZUH

We will generate a telemetry related to mimikatz and then generate a custom mimikatz alert. First we will make modifications in our ossec.conf file present on our agent. We will be needing sysmon logs for this. So make sure sysmon is installed.

#### Sysmon (System Monitor): 
is a Windows system service and driver that logs detailed system activity to the Windows Event Log. It is part of the Sysinternals Suite developed by Microsoft and is commonly used in security monitoring and threat detection. Sysmon tracks and logs events such as process creations, network connections, file changes, and more, which are helpful in detecting malicious behavior and investigating security incidents. These logs can be analyzed by SIEMs or security teams to detect anomalies, investigate attacks, and maintain a secure environment.

![image](https://github.com/user-attachments/assets/29bb34c9-1384-4564-8d31-d6ca45044376)

We will be ingesting sysmon logs, so coping the location to sysmon channel

![image](https://github.com/user-attachments/assets/234ad0ef-ff9f-4a4b-8668-1466af753471)

Add this name to conf file in log analysis section and remove other log forwarding and ingestion from this section

![image](https://github.com/user-attachments/assets/08fbf732-6716-4f8a-8c6a-fb989f13c5ec)

Save and restart wazuh service. Check for sysmon logs in wazuh events.

 #### Mimikatz:  

a widely recognized cybersecurity tool, used to extract sensitive information such as passwords, hashes, and Kerberos tickets from Windows systems. Originally developed for research purposes, it quickly became popular in both legitimate penetration testing and malicious activities, like credential theft and lateral movement in
networks. Its key features include Pass-the-Hash, Pass-the-Ticket, and Over-Pass-the-Hash attacks, making it a powerful tool for privilege escalation and post-exploitation activities. Despite its usefulness in security testing, Mimikatz is also commonly used in real-world attacks, making it a frequent target of detection by security tools.
Lets download mimikatz on windows 10. Exclude the folder from security for downloading mimikatz

![image](https://github.com/user-attachments/assets/e9abab25-cb45-4495-93f0-851f976ba7fc)

Download and execute mimikatz

![image](https://github.com/user-attachments/assets/36569fe1-7595-43cd-a65c-f48d00a6d3aa)

Check wazuh dashboard for any events

![image](https://github.com/user-attachments/assets/c328320f-5c70-4347-ba22-2c6443dc3c91)

We aren't getting any events so we will add rule to the ossec.conf file in wazuh manager and change

![image](https://github.com/user-attachments/assets/e1c66113-df4a-4c14-bcaa-220f6229b49d)

This changes in which format the logs should be dsplayed. Save and restart the wazuh manager. We created the following files and logs will be placed here.

![image](https://github.com/user-attachments/assets/3a5bcb7b-1af8-4880-8232-58cb26504bab)

In order for wazuh to start ingesting these logs we need to change configuration of filebeat. Change the archives value to true,

![image](https://github.com/user-attachments/assets/90ed5a66-19ef-42c2-bb51-32a3a520b8fe)

Save and restart filebeat. In wazuh move to stack management and then to index pattern.

![image](https://github.com/user-attachments/assets/20c00216-bfe5-4cdf-8f2d-f2dd880e948b)

We need to add index for the archives here so we can search the logs despite whether wazuh generates events or not.

![image](https://github.com/user-attachments/assets/b5737240-2dfb-41dc-9a6d-e48527c071fc)

![image](https://github.com/user-attachments/assets/b92815f5-47a6-4951-b58f-ce9d6bd8d236)

Now move to discover and select wazuh-archives, wait some time and the events related to mimikatz will be displayed.

![image](https://github.com/user-attachments/assets/e9513752-4b14-4ea6-880d-6690197b172f)

In wazuh only those logs will be shown that trigger a rule, so that's why we ingested all the logs regardless of any rule in the archives. We got 2 events for mimikatz and we will look at the one with event id 1 for process creation

![image](https://github.com/user-attachments/assets/ed7d17ea-b7bd-481f-8e41-a4dc33a8b0aa)

## GENERATING ALERT

We will generate our alert based on original file name so that if the attacker changes the file name he will not be able to bypass.

![image](https://github.com/user-attachments/assets/32235101-6bfb-4f0d-95b3-dcb58f26768e)

Lets create an alert using wwazuh rules present in /var/ossec/ruleset/rules in wazuh manager and can be accessed via
dashboard in management.

![image](https://github.com/user-attachments/assets/22d513e5-4e2a-44d8-8770-7eb871f358f7)

Move to manage rue files and search for sysmon rule for event id 1.

![image](https://github.com/user-attachments/assets/99c88f8a-1723-4244-9aa3-18902b6792d9)

![image](https://github.com/user-attachments/assets/f904c82d-f703-4bcf-85e4-269b0d514591)

Using this rule as reference we will built out our own custom rule formimikatz. We will edit the local_rules.xml file in custom rules.

![image](https://github.com/user-attachments/assets/4c0a28cd-326f-41ab-a8c9-6738448a6336)

Custom Rule For Mimikatz:

* Id will be 100002.

* The severity will be 15 that is the highest level.

* The originalFileName value should have mimikatz.exe

* Mitre value will be T1003 which means credential dumping which is what
mimikatz do.

![image](https://github.com/user-attachments/assets/4bb1938b-c31f-4619-b6d9-356a451b5d00)

Save the rule and then restart the manager.

### CHECKING THE ALERT

Execute mimikatz and then check if alert is generated in wazuh. I've changed the name of the mimikatz exe to check if it will detetct it.

![image](https://github.com/user-attachments/assets/9b869ffd-b86d-47ed-a227-055382a52520)

![image](https://github.com/user-attachments/assets/41bf1c82-7205-4b59-81e6-f2f8cbeaf0c8)

Wazuh detected the mimikatz execution even when we changed the name

![image](https://github.com/user-attachments/assets/ca6a82c2-1c93-4bcc-a47a-ae88aec397d3)

![image](https://github.com/user-attachments/assets/b20c0fc3-865f-4bad-af71-0bf2afe15574)

We have ingested sysmon logs into wazuh now we will automate the process using shuffle and hive.

## CONNECTING SHUFFLE

We will now connect shuffle which is our SOAR platform. Then send an alert to the hive and also the SOC analyst via an email. At the end we will have a fully functional lab having wazuh, the hive and shuffle.

** Shuffle: ** Shuffle is an open-source Security Orchestration, Automation, and Response (SOAR) platform designed to streamline security operations by automating repetitive tasks and integrating various security tools. It allows users to create automated workflows with a no-code or low-code interface, enabling quicker threat detection, incident response, and log analysis. By connecting systems like SIEMs, firewalls, and threat intelligence platforms, Shuffle SOAR enhances coordination and efficiency in responding to security incidents, reducing the need for manual intervention and improving overall security response times.
Head over to shuffle website, login and create a new workflow. Add a webhook from the triggers bar and then copy its URL to paste it in the ossec file.

![image](https://github.com/user-attachments/assets/57d40583-2bb1-4774-a016-a449d177bd4e)

Now select the change me icon and select the Execution Argument in the call section.

![image](https://github.com/user-attachments/assets/13bf52a6-eda5-49f5-9cb2-71dab612593f)

To integrate shuffle in wazuh we add the integration tag into the ossec file. This will tell the rule 10002 which we created for mimikatz to go to shuffle.

![image](https://github.com/user-attachments/assets/beed89b2-5e3c-45f3-b48a-ac2072328fdf)

Save the file and restart the manager.

### Testing Out The Integration

Execute mimikatz in windows and see if event is generated in shuffle. Start the webhook and look for events

![image](https://github.com/user-attachments/assets/334039d1-5963-41af-bf79-a718852b9d1a)

![image](https://github.com/user-attachments/assets/19f17798-0ec0-454a-a5c2-7465cf7f00c2)

### Workflow In Shuffle

The mimikatz alert will be sent to shuffle. The shuffle will extract the SHA256 of the file and then check reputation score using virustotal. It will send the details over to the hive to create alert. An email will be sent to SOC analyst for further investigation.
If we look at the events we see the hash value is appended by using SHA1=, to automate we need to parse the hash value out and send only the hash value not the SHA1= to VirusTotal. For doing this we will change the Change Me icon values.

![image](https://github.com/user-attachments/assets/9786a5c5-fce4-437e-b0a0-f4413d2156a1)

Rerun the workflow and check the change me value it is parsing the hash

![image](https://github.com/user-attachments/assets/96a0262c-e744-4402-b620-f195b3c3c0e0)

Once the hash is generated we will send it over to virus total to check the reputation score. We will use VirusTotal API so that it checks and sends us the result, create an account on VirusTotal and copy the API key.

![image](https://github.com/user-attachments/assets/2d379349-268e-45b4-91bb-7db681250bf1)

We will add virustotal to the workflow via the app and then add values to it. Use API key to authenticate.

![image](https://github.com/user-attachments/assets/3f3e4db6-e7c3-4324-a088-6d262d495804)

Rerun the workflow and we get the results from VirusTotal

![image](https://github.com/user-attachments/assets/f36b75ea-0d8d-4da3-bb81-995681e6ea6b)

![image](https://github.com/user-attachments/assets/a2631e80-347b-42f7-82b7-fb6c34fbc3b7)

## Sending Email To Analyst

Next step is to send an email to the analyst with information about detection. Select email from apps and add it to the workflow and connect it to Virus Total

![image](https://github.com/user-attachments/assets/9ebc85f1-e987-4fc4-a341-75ceb13520c4)

Now add the details for email which includes a valid email (disposable for demo purposes), the subject and details

![image](https://github.com/user-attachments/assets/0490c1c0-1386-4f6e-aa02-5db6d4186045)

Rerun the execution and see if the email is received in the inbox.

![image](https://github.com/user-attachments/assets/13eb50b7-19e0-4912-bebe-6e6167b9acc9)

### Email Received

![image](https://github.com/user-attachments/assets/a78bc7a2-16a3-45eb-a97b-87e8a5b5cbab)

### RESPONSIVE ACTION

We can add a response to perform an action that can be isolation of machine or blocking outbound traffic, disconnecting from the internet etc. We can also add a user input to perform the responsive action. 

## CONCLUSION
In this project we set up wazuh to receive alerts about mimikatz executed on a windows 10 machine. The alerts from wazuh are then forwarded to shuffle that is a SOAR platform and automates the received alerts to be sent to VirusTotal to get information about the executed file using its SHA256 value and then also sending an email to the SOC analyst about the detection.


