# Command Injection Log Investigation: whoami Detected in HTTP Request Body

<br>

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/Gits..png?raw=true" > 

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

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/1.png?raw=true" > 

To begin the investigation, I searched the log management system for all entries related to the web server IP `172.16.17.16`.  

This helps to:  
- Identify all requests made to the server around the alert time  
- Determine whether the `whoami` string appeared in other requests  
- Look for any patterns that indicate a **Command Injection attempt**  

By filtering the logs this way, we can see if the alert was an isolated event or part of a larger attack.

<img src="https://github.com/bayulus/Detecting-Command-Injection-Attacks/blob/main/img/3.png?raw=true" > 

The search returned **5 log entries** from the source IP `61.177.172.87` to our web server `172.16.17.16`.  

We will now analyze each log entry one by one to understand what the attacker may be attempting and whether any **Command Injection** was attempted or successful. 




