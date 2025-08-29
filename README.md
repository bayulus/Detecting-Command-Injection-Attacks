# Command Injection Log Investigation: whoami Detected in HTTP Request Body

<br>

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/Gits.png?raw=true" > 

<p>In this project, I investigate a potential Command Injection attack observed in web server logs, specifically the detection of the <b><i>whoami</i></b> command within the request body. Command Injection is a critical vulnerability listed in the OWASP Top 10, and this project focuses on analyzing whether the activity represents a false positive or a real exploitation attempt.

I take a step-by-step approach to review the evidence, validate if the command was successfully executed, and highlight methods to identify such attacks during log analysis. By walking through the investigation process, I demonstrate how to distinguish harmless anomalies from genuine threats and how to assess the impact of a possible injection on a web application.

This project aims to offer a practical and investigative approach to detecting and analyzing command injection attempts using real-world log data.</p>

<h2>What Is Command Injections</h2>

What is Command Injection?

Before diving into the investigation, it is important to explain what Command Injection means.

Command Injection is a serious security vulnerability that allows an attacker to run system-level commands through a vulnerable application. Instead of only processing valid input, the application mistakenly passes attacker-supplied data to the underlying operating system for execution.

Attackers often test for this vulnerability by submitting simple commands like whoami to check which account the server is running under. However, they do not stop there. Once they confirm the application is vulnerable, they may try additional commands to explore or manipulate the system, such as:

- `whoami` → check which account the server is running under  
- `dir` or `ls` → list directory contents  
- `cat` or `type` → read file contents (e.g., `/etc/passwd` on Linux)  
- `cp` → copy files  
- `rm` → delete files  
- `ping` or `curl` → test network connections or download malicious tools
  
That is why it is very important to inspect user input carefully and look for keywords or patterns related to terminal commands. During log analysis, seeing these keywords in request parameters, headers, or body content is a strong signal of a potential Command Injection attempt.


<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/1.png?raw=true" > 

This alert shows an incoming HTTP **POST** request from source IP `61.177.172.87` to our web server `WebServer1004` (`172.16.17.16`).  
The rule **SOC168 - Whoami Command Detected in Request Body** was triggered because the request body contained the string `whoami`.  
Since the **Device Action = Allowed**, the request was not blocked. This could indicate an attempt to perform **Command Injection** to identify the server’s running user. 

## Step 1: Check Web Server Logs

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/2.png?raw=true" > 

To begin the investigation, I searched the log management system for all entries related to the web server IP `172.16.17.16`.  

This helps to:  
- Identify all requests made to the server around the alert time  
- Determine whether the `whoami` string appeared in other requests  
- Look for any patterns that indicate a **Command Injection attempt**  

By filtering the logs this way, we can see if the alert was an isolated event or part of a larger attack.

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/3.png?raw=true" > 

The search returned **5 log entries** from the source IP `61.177.172.87` to our web server `172.16.17.16`.  

We will now analyze each log entry one by one to understand what the attacker may be attempting and whether any **Command Injection** was attempted or successful. 

#### 📝 Log Entry 1

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/4.png?raw=true" > 

**Analysis:** At **04:12 AM** on Feb 28, 2022, the source IP `61.177.172.87` connected to our web server `172.16.17.16` over HTTPS (port 443) and issued a **POST** request to `/video/`.  The request contained the parameter `?c=whoami`, which suggests an attempt at **Command Injection** to check the server’s running user.  

The server responded with **HTTP 200** and a response size of 912 bytes, meaning the request was successfully processed. This does not confirm execution yet, but it shows the server accepted the input instead of rejecting it.  

#### 📝 Log Entry 2

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/5.png?raw=true" > 

**Analysis:** At **04:11 AM** on Feb 28, 2022, the source IP `61.177.172.87` made another **POST** request to `/video/` on our web server.  

This time, the parameter was `?c=ls`, which is typically used to **list directory contents**. This shows the attacker is moving beyond simple probing (`whoami`) and trying to **enumerate files/folders** on the server.  

The server responded with **HTTP 200 (OK)** and a response size of **1021 bytes**.  
- The **200 status code** means the request was accepted and processed.  
- Compared to Log Entry 1 (912 bytes), the **larger response size** suggests the output of `ls` may have been returned, since directory listings generally produce more content than the single output of `whoami`.  

This points toward the request being **processed successfully** and increasing the likelihood that the command was actually executed.  

#### 📂 Log Entry 3  

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/6.png?raw=true" > 

**Analysis:** The attacker next used the parameter `?c=uname`, a command commonly used to gather **system information** such as the operating system name and version.  

The server again replied with **HTTP 200 (OK)** and a response size of **910 bytes**.  
- The status code shows the request was processed.  
- The smaller response size compared to the previous `ls` request suggests the output was shorter, which aligns with what `uname` would typically return (just a few words describing the OS).  

This indicates the attacker is now performing **system reconnaissance** after confirming possible command execution.  

#### 📑 Log Entry 4  

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/7.png?raw=true" > 

The attacker then issued the parameter `?c=cat /etc/passwd`, a well-known attempt to **read sensitive system files**. The `/etc/passwd` file on Linux contains user account details and, if exposed, can help attackers with privilege escalation or password cracking.  

The server responded with **HTTP 200 (OK)** and a larger response size of **1321 bytes**.  
- The success status means the request was processed.  
- The increase in response size compared to earlier commands suggests that actual file content may have been returned.  

This is a strong indicator of a **successful Command Injection**, as the attacker appears to have retrieved system information from a protected file.  


#### 📌📑  Log Entry 5  

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/8.png?raw=true" > 

The final log entry shows the attacker attempting `?c=cat /etc/shadow`, a critical system file on Linux that stores **hashed passwords**. Accessing this file can allow attackers to **crack passwords** and escalate privileges.  

The server responded with **HTTP 200 (OK)** and a response size of **1501 bytes**.  
- The status code confirms the request was processed.  
- The larger response size compared to previous entries suggests that the file content may have been returned.  

This entry represents a **high-risk Command Injection attempt**, showing the attacker moving from reconnaissance (`whoami`, `uname`, `ls`) to attempting access to sensitive system data.  

---

The differing **response sizes** across the POST requests suggest that the commands may have been executed. To verify this, we now move to **Step 2: Checking the Web Server’s Command History**, where we will examine whether the POSTed commands were actually run on the server.

<br>

## Step 2: Checking the Web Server’s Command History

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/9.png?raw=true" >

After checking the terminal history of the web server, we can clearly see that the commands were executed. This confirms that the POST parameters were successfully run and that the web server has been compromised.

Just to cross-check, let’s review the running processes on the web server to determine if any suspicious or unauthorized activity is present.

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/10.png?raw=true" >

As we can see, the process history shows that the commands were executed under a **high-privilege account (root)**. This confirms that the web server is compromised. At this point, the priority is to **contain the affected server** and escalate the case for **further investigation and mitigation** to prevent additional damage.

<br>

## Step 4: Contain the Affected Host 

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/11.png?raw=true" >

Since the web server has been confirmed as **compromised** and the malicious commands were executed with **root privileges**, immediate **containment** is required.  

Actions to take:  
- Isolate the host from the network to prevent further spread.  
- Stop or suspend suspicious processes.  
- Preserve forensic artifacts (logs, memory, binaries) for investigation.  
- Prepare the host for escalation to the incident response team.

<br>

## Step 5: Investigate the Attacker’s IP  

We already know the **source IP** belongs to the attacker. To gather further intelligence, we will check the **IP reputation and geolocation** using tools such as **AbuseIPDB**.  

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/12.png?raw=true" >

As you can see, the source IP address originates from **China** and has been reported multiple times in **AbuseIPDB**, confirming its association with malicious activity.  

This intelligence can be leveraged to:  
- Block the IP address at the firewall or WAF.  
- Add detection rules for similar activity.  
- Feed into threat intelligence for future correlation.

<br>

## Final Review and Mitigation  

Now that we know the system is **compromised** and has been **contained**, the next steps are to perform a thorough **incident response (IR)**:  

- Stop any **malicious or suspicious processes** running on the affected host.  
- Check for any remaining **malicious activity** to ensure the attacker has not left backdoors.  
- Verify that the attacker has not moved laterally to other hosts, especially since they may have had access to hashed passwords (`/etc/shadow`).  
- Apply necessary **patches, password resets, and monitoring** to secure the environment.  

These actions ensure that the compromise is fully mitigated and reduce the risk of further exploitation.

<br>


## Protecting Against Command Injection  

1. **Input Validation**  
   - Strictly validate and sanitize all user inputs.  
   - Only allow expected characters, lengths, and types (e.g., alphanumeric).  

2. **Use Parameterized APIs**  
   - Avoid passing user input directly to system commands.  
   - Use safe APIs or libraries that separate code from data.  

3. **Least Privilege Principle**  
   - Run web servers and applications with the minimum privileges necessary.  
   - Avoid running processes as root or administrator.  

4. **Escape User Input**  
   - Properly escape any user-supplied data if it must be used in system commands.  

5. **Disable Unnecessary System Commands**  
   - Restrict the set of commands the application can execute.  

6. **Logging and Monitoring**  
   - Continuously monitor logs for suspicious patterns like `whoami`, `ls`, `cat`, etc.  
   - Set up alerts for unusual command execution attempts.  

7. **Web Application Firewalls (WAF)**  
   - Use a WAF to block known attack patterns and malicious input strings.  

8. **Regular Security Testing**  
   - Conduct code reviews, penetration testing, and vulnerability scanning.  
   - Keep software and libraries up-to-date.

## Conclusion  

From the investigation, we confirmed that the web server was compromised through a command injection vulnerability.  
The attacker successfully executed commands with root privileges, which posed a critical security risk.  
Containment measures were applied to stop the ongoing processes, block the malicious IP address, and isolate the host.  

Moving forward, thorough incident response steps must be taken to:  
- Remove any remaining malicious activity,  
- Ensure no lateral movement occurred across the network, and  
- Apply long-term fixes (secure coding, patching, and continuous monitoring).  

This case highlights the importance of proactive security controls, proper input validation, and regular security testing to prevent command injection attacks.  

[![Static Badge](https://img.shields.io/badge/%20Please%20click%20here%20to%20explore%20additional%20projects-blue?style=for-the-badge)](https://github.com/bayulus/)
  

















