# 🚨 Incident Response: Brute Force Attempt Detection


---

![image](https://github.com/user-attachments/assets/01df8a67-e9bf-4f0b-a780-de02f194826c)


---

# Scenario

As a security analyst for a healthcare provider with a distributed workforce and a strong dependency on Azure Virtual Desktop, I noticed a surge in failed authentication attempts targeting clinician and administrative accounts late at night. These login attempts were traced back to unfamiliar IP addresses and showed a consistent pattern across multiple user accounts.

Given the critical nature of healthcare data and compliance requirements, I suspected a brute-force or credential-stuffing attempt aimed at gaining unauthorized access. My objective was to investigate the incident, assess exposure, and contain any threats in alignment with NIST SP 800-61 incident response procedures.

---

## 🔍 **Objective: Find Brute Force and Create Sentinel Scheduled Query Rule**
Implement a **Sentinel Scheduled Query Rule** using KQL in Log Analytics to detect when the same remote IP address fails to log in to the same Azure VM 10+ times within a 5-hour period.

---

## 🛠️ **Platforms and Tools**
- **Microsoft Sentinel**
- **Microsoft Defender for Endpoint**
- **Kusto Query Language (KQL)**
- **Windows 10 Virtual Machines (Microsoft Azure)**

---
