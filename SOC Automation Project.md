SHUFFLE

![C:\Users\Adeen\Downloads\SOC
Analyst1.drawio.png](media/image1.png){width="6.5in"
height="7.227344706911636in"}

**SETTING UP WAZUH**

We will send telemetry containing mimikatz to wazuh. The wazuh will
trigger mimikatz custom alert.

We will be using windows 10 named DFIR with sysmon already installed.

We need to make changes in the ossec file for log ingestion.

**Wazuh Installation**

Install Wazuh 4.7

curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash
./wazuh-install.sh -a

Extract Wazuh Credentials

sudo tar -xvf wazuh-install-files.tar

![](media/image2.png){width="6.5in" height="1.7534722222222223in"}

![](media/image3.png){width="6.5in" height="1.645138888888889in"}

![](media/image4.png){width="6.5in" height="2.2020833333333334in"}

![](media/image5.png){width="6.5in" height="3.207638888888889in"}

Add agent windows 10 to the wazuh

![](media/image6.png){width="6.5in" height="3.1729166666666666in"}

Invoke-WebRequest -Uri
https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile
\${env.tmp}\wazuh-agent; msiexec.exe /i \${env.tmp}\wazuh-agent /q
WAZUH_MANAGER=\'192.168.198.132\' WAZUH_AGENT_NAME=\'DFIR\'
WAZUH_REGISTRATION_SERVER=\'192.168.198.132\'

![](media/image7.png){width="6.5in" height="0.8944444444444445in"}

![](media/image8.png){width="6.5in" height="1.1354166666666667in"}

The agent is active in wazuh dashboard.

![](media/image9.png){width="6.5in" height="3.079861111111111in"}

We have successfully configured wazuh and the hive. Our end goal is to
detect mimikatz on our endpoint machine (windows 10), for that we will
generate telemetry and generate an alert related to mimikatz.

**GENERATING TELEMETRY AND INGESTING LOGS IN WAZUH**

We will generate a telemetry related to mimikatz and then generate a
custom mimikatz alert.

First we will make modifications in our ossec.conf file present on our
agent. We will be needing sysmon logs for this. So make sure sysmon is
installed.

![](media/image10.png){width="6.5in" height="1.6805555555555556in"}

We will be ingesting sysmon logs so chaning the location to sysmon
channel

![](media/image11.png){width="6.5in" height="4.745138888888889in"}

Add this name to conf file in log analysis section and remove other log
forwarding and ingestion from this section

![](media/image12.png){width="6.5in" height="2.332638888888889in"}

Save and restart wazuh service.

Checking sysmon logs in wazuh events.

Mimikatz: a widely recognized cybersecurity tool, used to extract
sensitive information such as passwords, hashes, and Kerberos tickets
from Windows systems. Originally developed for research purposes, it
quickly became popular in both legitimate penetration testing and
malicious activities, like credential theft and lateral movement in
networks. Its key features include Pass-the-Hash, Pass-the-Ticket, and
Over-Pass-the-Hash attacks, making it a powerful tool for privilege
escalation and post-exploitation activities. Despite its usefulness in
security testing, Mimikatz is also commonly used in real-world attacks,
making it a frequent target of detection by security tools.

Lets download mimikatz on windows 10. Exclude the folder from security
for downloading mimikatz

![](media/image13.png){width="6.5in" height="2.7055555555555557in"}

Download and execute mimikatz

![](media/image14.png){width="6.5in" height="1.5909722222222222in"}

Check wazuh dashboard for any events

![](media/image15.png){width="6.5in" height="2.111111111111111in"}

We aren't getting any events so we will add rule to the ossec.conf file
in wazuh manager and change

![](media/image16.png){width="6.5in" height="1.4076388888888889in"}

This changes in which format the logs should be dsplayed. Save and
restart the wazuh manager.

We created the following files and logs will be placed here.

![](media/image17.png){width="6.5in" height="0.9208333333333333in"}

In order for wazuh to start ingesting these logs we need to change
configuration of filebeat. Change the archives value to true,

![](media/image18.png){width="6.5in" height="2.401388888888889in"}

Save and restart filebeat. In wazuh move to stack management and then to
index pattern.

![](media/image19.png){width="6.5in" height="3.227777777777778in"}

We need to add index for the archives here so we can search the logs
despite whether wazuh generates events or not.

![](media/image20.png){width="6.5in" height="2.7708333333333335in"}

![](media/image21.png){width="6.5in" height="1.304861111111111in"}

Now move to discover and select wazuh-archives, wait some time and the
events related to mimikatz will be displayed.

![](media/image22.png){width="6.020833333333333in"
height="1.9583333333333333in"}

In wazuh only those logs will be shown that trigger a rule, so that's
why we ingested all the logs regardless of any rule in the archives.

We got 2 events for mimikatz and we will look at the one with event id 1
for process creation

![](media/image23.png){width="6.5in" height="2.8333333333333335in"}

**GENERATING ALERT**

We will generate our alert based on original file name so that if the
attavker changes the file name he will not be able to bypass.

![](media/image24.png){width="6.5in" height="2.3472222222222223in"}

Lets create an alert using wwazuh rules present in
/var/ossec/ruleset/rules in wazuh manager and can be accessed via
dashboard in management.

![](media/image25.png){width="6.5in" height="2.7527777777777778in"}

Move to manage rue files and search for sysmon rule for event id 1.

![](media/image26.png){width="6.5in" height="1.9152777777777779in"}

![](media/image27.png){width="6.5in" height="2.6145833333333335in"}

Using this rule as reference we will built out our own custom rule for
mimikatz. We will edit the

local_rules.xml file in custom rules.

![](media/image28.png){width="6.5in" height="1.4493055555555556in"}

Custom Rule For Mimikatz:

Id will be 100002.

The severity will be 15 that is the highest level.

The originalFileName value should have mimikatz.exe

Mitre value will be T1003 which means credential dumping which is what
mimikatz do.

![](media/image29.png){width="6.5in" height="2.5555555555555554in"}

Save the rule and then restart the manager.

CHECKING THE ALERT

Execute mimikatz and then check if alert is generated in wazuh. Ive
changed the name of the mimikatz exe to check if it will detetct it.

![](media/image30.png){width="6.5in" height="1.3340277777777778in"}

![](media/image31.png){width="6.5in" height="1.4868055555555555in"}

Wazyh detected the mimikatz execution even when we changed the name

![](media/image32.png){width="6.5in" height="2.685416666666667in"}

![](media/image33.png){width="6.5in" height="2.796527777777778in"}

We have ingested sysmon logs into wazuh now we will automate the process
using shuffle and hive.

**CONNECTING SHUFFLE**

We will now connect shuffle which is our SOAR platform. Then send an
alert to the hive and also the SOC analyst via an email. At the end we
will have a fully functional lab having wazuh, the hive and shuffle.

Head over to shuffle website, login and create a new workflow. Add a
webhook from the triggers bar and then copy its URL to paste it in the
ossec file.

![](media/image34.png){width="6.046042213473316in"
height="2.8815594925634294in"}

Now select the change me icon and select the Execution Argument in the
call section.

![](media/image35.png){width="6.042260498687664in"
height="3.8835728346456695in"}

To integrate shuffle in wazuh we add the integration tag into the ossec
file. This will tell the rule 10002 which we created for mimikatz to go
to shuffle.

![](media/image36.png){width="6.5in" height="2.1875in"}

Save the file and restart the manager.

Testing out the integration

Execute mimikatz in windows and see if event is generated in shuffle.

Start the webhook and look for events

![](media/image37.png){width="5.726618547681539in"
height="3.928483158355206in"}

![](media/image38.png){width="6.002588582677165in"
height="4.202452974628171in"}

WORKFLOW

The mimikatz alert will be sent to shuffle. The shuffle will extract the
SHA256 of the file and then check reputation score using virustotal. It
will send the details over to the hive to create alert. An email will be
sent to SOC analyst for further investigation.

If we look at the events we see the hash value is appended by using
SHA1=, to automate we need to parse the hash value out and send only the
hash value not the SHA1= to VirusTotal. For doing this we will change
the Change Me icon values.

![](media/image39.png){width="5.841954286964129in"
height="3.990130139982502in"}

Rerun the workflow and check the change me value it is parsing the hash

![](media/image40.png){width="5.909943132108486in"
height="3.7612740594925635in"}

Once the hash is generated we will send it over to virus total to check
the reputation score. We will use VirusTotal API so that it checks and
sends us the result, create an account on VirusTotal and copy the API
key.

![](media/image41.png){width="6.5in" height="2.3944444444444444in"}

We will add virustotal to the workflow via the app and then add values
to it. Use APAi key to authenticate.

![](media/image42.png){width="6.029507874015748in"
height="3.394819553805774in"}

Rerun the workflow and we get the results from virustotal

![](media/image43.png){width="6.5in" height="3.365972222222222in"}

![](media/image44.png){width="6.5in" height="3.908333333333333in"}

**Sending Email**

Next step is to send an email to the analyst with information about
detection.

Select email from apps and add it to the workflow and connect it to
virus total

![](media/image45.png){width="6.5in" height="2.3055555555555554in"}

Now add the details for email which includes a valid email (disposable
for demo purposes), the subject and details

![](media/image46.png){width="6.5in" height="4.313888888888889in"}

Rerun the execution and see if the email is received in the inbox.

![](media/image47.png){width="6.5in" height="3.9659722222222222in"}

Email received

![](media/image48.png){width="6.5in" height="2.477777777777778in"}

![](media/image49.png){width="6.5in" height="3.2819444444444446in"}

RESPONSIVE ACTION

Now we will add a response to perform an action that can be isolation of
machine or blocking outbound traffic, disconnecting from the internet
etc.

We will use a user input to perform the responsive action. We will block
the ip of the infected machine. We will add the user input in the
workflow

![](media/image50.png){width="6.375in" height="4.041666666666667in"}

Add the email that will ask for input

![](media/image51.png){width="6.5in" height="3.4972222222222222in"}

We will add wazuh and connect it to the user input. Based on input wazuh
will perform the blocking.

that will manage the agent to is to be blocked.

![](media/image52.png){width="6.0in" height="2.875in"}

In order to use wazuh in shuffle wew first add the GET-API in the
workflow and make sure all inbound traffic to port 55000 is allowed. The
reason we are doing this is because if we want to use wazuh API
capability we must first authenticate and get a Jason Web Token and to
initiate that we use curl.

The wazuh account we will be using is the wazuh-uri

![](media/image53.png){width="6.5in" height="3.658333333333333in"}

Change the user and pass along with wazuh IP.

Now we will configure wazuh in shuffle

In the API key we will use GET-API

![](media/image54.png){width="6.5in" height="3.495138888888889in"}

For agents list we will add the associated agent id present in wazuh
dashboard.

![](media/image55.png){width="6.5in" height="1.7125in"}

![](media/image56.png){width="6.5in" height="3.1055555555555556in"}

For more fields we must first configure active response on our wazuh
manager. We will create an active response tag and make sure the command
reflects the command name we want to use.

Location local means the host that generated the alert. Level of alert
will be 5 and no timeout.

![](media/image57.png){width="6.5in" height="1.9875in"}

Restart the wazuh manager. When we use active response especially in
terms of API, the command name appends the timeout to the name but it is
hidden. For example our command name was ***firewall-drop*** but if we
want to use it with API we must appwnd the timeout. Since we set the
timeout to no we will append 0 to it ***firewall-drop0.*** One way to
see the name and if the script is active is by using agent control
binary located under /var/ossec/bin

![](media/image58.png){width="6.5in" height="1.5131944444444445in"}

![](media/image59.png){width="6.5in" height="3.15625in"}

We can see the list of active responses by using the L flag.

![](media/image60.png){width="6.5in" height="0.8444444444444444in"}

And from this we can see the name we need to use to utilize the API.

We will us the following command to check if active response is working

./agent_control --b 8.8.8.8 --f firewall-drop0 --u 001

-b says block the DNS, -f refers to the active response name and --u
flag is used for agent id. It means that block the DNS server 8.8.8.8 on
the agent having id 001 using acitive response firewall-drop0.

Lets ping 8.8.8.8 from our agent before running this command

![](media/image61.png){width="6.5in" height="1.5527777777777778in"}
