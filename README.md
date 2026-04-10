Open cybersecurity audit AI

Overview
Open Cybersecurity Audit AI is an AI-assisted web security testing platform designed to identify vulnerabilities that traditional scanners often fail to detect. Most existing tools rely heavily on static crawling and predefined vulnerability signatures, which limits their effectiveness in modern web applications where issues often arise only after user interaction.This system takes a different approach by launching a real browser session guided by an AI agent. The agent interacts with the application in a human-like manner by clicking elements, filling forms, and navigating through authenticated flows. During this process, all network activity is captured and analyzed. A dedicated data flow tracking system monitors how sensitive information such as passwords, tokens, and personal data propagates across requests, cookies, and browser storage. The platform then performs targeted vulnerability detection, including Cross-Site Scripting (XSS) and SQL Injection (SQLi), based on the observed application behavior.By combining real user simulation with end-to-end data tracking, Open Cybersecurity Audit AI not only identifies vulnerabilities but also provides insight into how sensitive data is exposed within the system.

System Overview
The platform is designed as a modular pipeline where a target web application is analyzed through multiple stages, resulting in a structured security report.
<img width="500" height="707" alt="Screenshot 2026-04-10 114641" src="https://github.com/user-attachments/assets/840a6d92-01dd-4966-afe6-359e8dbbd60b" />





