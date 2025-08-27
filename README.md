# Command Injection Log Investigation: whoami Detected in HTTP Request Body

<br>

<p>In this project, I investigate a potential Command Injection attack observed in web server logs, specifically the detection of the <b><i>whoami</i></b> command within the request body. Command Injection is a critical vulnerability listed in the OWASP Top 10, and this project focuses on analyzing whether the activity represents a false positive or a real exploitation attempt.

I take a step-by-step approach to review the evidence, validate if the command was successfully executed, and highlight methods to identify such attacks during log analysis. By walking through the investigation process, I demonstrate how to distinguish harmless anomalies from genuine threats, and how to assess the impact of a possible injection on a web application.

This project is designed to provide a practical and investigative perspective on detecting and analyzing command injection attempts through real-world log data.</p>
