[Log monitoring](https://docs.google.com/open?id=1z1tUcwOgueH0ryk1o0eCjLZiWUj--a0HlN8yc3dQx3U)

Log Monitoring

Linux Logs







1. Executive Summary
1. Objective: To keep track of web server?s activities and create a script to monitor web access logs on Linux systems.The scripts flags unusual access patterns tracking 404 errors and urgent logs detected entries.
1. Importance: Monitoring web server access logs is important to identify potential unauthorized access attempts by detecting patterns such as repeated 404 errors which may indicate probing sensitive data
1. Outcome: Expected result is a functional script that logs access activities, counts event types and trigger alerts threshold when exceeded, and triggers notifications.


1. Introduction


The log monitoring is designed to detect unusual access patterns in a Linux environment. The monitoring solution consists of a Bash script to analyze access logs, scheduled to run using a cron job. The script identifies 404 errors which indicate failed access attempts to web resources and urgent log detected entries signaling critical events





1. Documentation of Network Devices




1. Tools used: bash, linux, kali openvas, python
1. Log file to be monitored(sample.txt)  
In this workflow, multiple requests are executed to a website, purposefully causing "404 Not Found" errors to simulate unauthorized access attempts. The log monitoring system is configured to detect these error patterns and generates an alert when five or more such errors occur within one minute. This alert is then stored in a designated folder, which can be accessed for review or integrated with other notification services for real-time alerts.

The Apache web server manages the logs, utilizing log rotation to organize old entries, while a Bash script (monitor_log.sh) continuously checks the access.log and error.log files for new lines. When new data is logged, a Python thread processes this data and sends it to a central server. The server.py script classifies the logs into "access," "error," or "unknown" categories. Additionally, log_monitor.py actively scans these categorized logs for urgent patterns, such as repeated 404 errors, and triggers alerts whenever thresholds are exceeded.

















1. Script Code and Explanation


1. Log parsing with Python Script
The script monitors a log file (sample.txt) for specific entries, logs the results, and sends email alerts if certain thresholds are met.

1. Imports:
1. re: provides regular expression matching support, datetime for timestamp logs.
1. smtplib and MIMEText:  send email alerts via an SMTP server.
1. Configuration Variables:
1. log_file: Specifies (sample.txt) that the script will analyze.
1. threshold: Sets a threshold for triggering alerts. An alert is triggered if either type of log entry (e.g., "404 errors" or "Urgent logs") exceeds this count (3).
1. Functions:
1. parse_log(file) reads through each line,counts the occurrences of "404" indicating failed access and "Urgent log detected" entries.
1. generate_alert(error_count, urgent_count):compares the counts of "404" "Urgent log detected" entries against the threshold.If either count exceeds the threshold, it calls send_email_alert to email the alert.
1. send_email_alert(message):Sets up the email headers and connects to the SMTP server.Uses starttls() to secure the connection.Prints a success message if the email is sent successfully. Otherwise,print errors and include error handling. 
1. log_results(error_count, urgent_count):Logs the current count of "404" errors and "Urgent logs" to (log_monitoring_report.txt) with timestamp 
1. Main Execution:
1. If the script is executed directly, it calls parse_log to analyze the log file, calls generate_alert to trigger an alert if the counts exceed the threshold and calls log_results to record the findings in log_monitoring_report.txt.
This Python script automates the process of monitoring a log file (sample.txt) for failed access attempts and urgent events.It also keeps a record of each monitoring session in log_monitoring_report.txt, with timestamps for future reference. This enhances security monitoring, making it easier for administrators to respond to and track abnormal access patterns.











1. Monitoring Script with Bash
This Bash script provides a straightforward way to monitor (sample.txt) for specific types of events, namely 404 errors and "Urgent log detected" entries. The script counts these occurrences, checks if they exceed a defined threshold, and logs the results.

1. Log File Definition:
1. The script specifies sample.txt as the log file to analyze
1. Counting Specific Log Entries:
1. It uses grep to search for lines containing specific keywords:404 errors( counts occurrences of the term 404 in the log file, indicating failed access attempts) and Urgent Logs:(counts occurrences of "Urgent log detected," which signifies security events)
1. These counts are saved as error_count and urgent_logs
1. Threshold for Alerts:
1. The value is set at 3. If it exceeds this threshold, an alert message is printed and it allows the system to identify and flag unusual activity in the log file
1. Results with Timestamps:
1. Each time the script runs, it appends a new entry to (log_monitoring_report.txt) and this includes the current date and time and counts of 404 errors and urgent logs
This Bash script serves as an effective tool for log monitoring. It enables real-time alerting when certain types of log entries (such as 404 errors and urgent events) exceed a specified threshold. By recording each check in log_monitoring_report.txt, the script provides ongoing documentation of log activity, supporting timely detection and response to potential issues.







1. Automating log monitoring with Cron  


The crontab scheduler is used to ensure continuous monitoring of the sample.txt log file without manual intervention.It commands to run automatically at specified times or intervals.

1. Run Automatically: The cron job executes monitor_log.py every 10 minutes without manual oversight.
1. Generate Alerts and Log Results: Each time the script runs, it scans sample.txt for 404 errors and urgent log entries, checks them against the defined threshold, and logs the results to log_monitoring_report.txt. If the counts exceed it triggers an email notification.
1. Provide Consistent Log Tracking: ensures a reliable history of log activity in log_monitoring_report.txt
This setup allows the system administrator to identify patterns of errors or urgent events quickly.The system supports proactive security and system management.











1. Potential Iterations and Enhancements


1. Enhanced Monitoring:
1. Sample.txt is scanned for basic error patterns (404 errors and "Urgent log detected"). By adding advanced rules to detect patterns (e.g., repeated failed attempts from the same IP within a short time), the script could flag potential brute-force attacks or suspicious access patterns, further enhancing security monitoring
1. Integrated Notification System:
1. While email notifications are currently configured, adding alternative notification channels, such as SMS, or integration with third-party incident management systems, would improve the timeliness and visibility of alerts to ensure critical alerts are promptly addressed.
1. Encryption:
1. Log entries in sample.txt are processed directly, and output is written to log_monitoring_report.txt without encryption. Encrypting these files during transmission would secure sensitive data
1. Code Structure:
1. Refactoring the monitoring script using modular functions or implementing design patterns, would enhance scalability and readability and adding new log filters can then be done
1. Log Rotation and Archiving:
1. To manage growing log files and ensure older logs are retained without overwhelming the system, implementing automated log rotation and archiving for log_monitoring_report.txt would be beneficial. Archiving older log files to a separate storage solution, such as Amazon S3 would optimize storage.
1. Machine Learning for Anomaly Detection:
1. Leveraging machine learning could help identify anomalies in the logs based on historical data patterns. Anomaly detection algorithms could flag unusual patterns in sample.txt based on previous data trends, offering a more dynamic and predictive approach to monitoring.
1. Visualization and Reporting:
1. Adding a visualization tool or dashboard (e.g., using Grafana or Kibana) to display the data from log_monitoring_report.txt would enable real-time monitoring and insights. Visual charts of error trends, or event frequency would allow administrators to identify patterns more quickly.
1. Improved Log Storage:
1. Storing logs in a database instead of a flat file (log_monitoring_report.txt) would facilitate rapid retrieval of historical data and easier to filter by date, error type, and other comprehensive analytics.


1.  Input Sanitization:
1. Entries in sample.txt should be sanitized before processing. This will prevent malicious log entries from being inadvertently executed and protect against the exploitation of remote services.
1. Advanced Alerting and Threshold Adjustments:
1. Instead of a fixed threshold, adaptive thresholds could be applied, adjusting based on normal daily or weekly log activity( higher activity during business hours and lower thresholds after-hours) would allow for a more flexibility




1. Conclusion
This log monitoring project establishes an essential framework for identifying critical events and potential security issues on Linux systems. By automating the detection of 404 errors and urgent log entries in sample.txt, the system provides timely alerts and detailed logs that support proactive monitoring and swift response to anomalies.

To further enhance this solution, integrating additional tools and approaches could strengthen both its effectiveness and scalability:Database Integration, Visualization and Analytics Dashboard,Cross-System Monitoring, Anomaly Detection with Machine Learning and Enhanced Alerting Mechanisms.With these enhancements, this log monitoring solution can evolve into a flexible system. The organization would benefit from a layered approach to monitoring and analytics and robust cybersecurity posture.



1. Reference/s


MITRE ATT&CK. (n.d.). Network Sniffing. MITRE ATT&CK. Retrieved November 6, 2024, from https://attack.mitre.org/techniques/T1040/



OSSEC. (n.d.). Documentation. OSSEC. Retrieved November 6, 2024, from https://www.ossec.net/docs/index.html



Gift, N. (2024, January 18). Designing and implementing monitoring and alerting. In AWS Certified Security ? Specialty (SCS-C02) Cert Prep: 2 Security Logging and Monitoring. LinkedIn Learning. https://www.linkedin.com/learning/aws-certified-security-specialty-scs-c02-cert-prep-2-security-logging-and-monitoring/designing-and-implementing-monitoring-and-alerting-22888446?contextUrn=urn%3Ali%3AlyndaLearningPath%3A65c678dc498e16141f852180&resume=false&u=0



Brennen, J. (2023, February 22). A9: Security logging and monitoring failures. In Static Application Security Testing. LinkedIn Learning. https://www.linkedin.com/learning/static-application-security-testing/a9-security-logging-and-monitoring-failures?u=0



BigPanda. (n.d.). Improve IT alert management. BigPanda. Retrieved November 6, 2024, from https://www.bigpanda.io/blog/improve-it-alert-management/



Landauer, M., Onder, S., Skopik, F., & Wurzenberger, M. (2023). Deep learning for anomaly detection in log data: A survey. Machine Learning with Applications, 12, 100470. https://doi.org/10.1016/j.mlwa.2023.100470



Graylog. (2022, July 7). Centralized log management for network monitoring. Graylog. Retrieved November 6, 2024, from https://graylog.org/post/centralized-log-management-for-network-monitoring/



MetricFire. (2023, July 16). Grafana vs Kibana. Medium. Retrieved November 6, 2024, from https://medium.com/@MetricFire/grafana-vs-kibana-ddd35b460b58



Stack Overflow. (n.d.). Is it faster to access data from files or a database server? Stack Overflow. Retrieved November 6, 2024, from https://stackoverflow.com/questions/2147902/is-it-faster-to-access-data-from-files-or-a-database-server



OpenAI. (2024). ChatGPT Mini-O [Large language model]. Python script: monitor_log.py. OpenAI. Retrieved November 6, 2024, from https://platform.openai.com



Lighthouse Labs. (n.d.). W03D5 Activities. Lighthouse Labs. Retrieved November 6, 2024, from https://web.compass.lighthouselabs.ca/p/cyber/days/w03d5/activities/2947



Lighthouse Labs. (n.d.). W03D5 Activities. Lighthouse Labs. Retrieved November 6, 2024, from https://web.compass.lighthouselabs.ca/p/cyber/days/w03d5/activities/2945













1. Revision History




