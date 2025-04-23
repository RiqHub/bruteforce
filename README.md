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

## **Incident Response Phases**
### 1️⃣ Preparation
1. **Policies and Procedures:**
   - Establish protocols for handling brute-force attempts, account lockouts, and account recovery.
   - Include predefined actions for notifications, account lockdowns, and reporting suspicious activity.

2. **Access Control and Logging:**
   - Enable logging of all login attempts across Azure AD.
   - Integrate with **Microsoft Defender for Identity** and **Azure Sentinel** for automated detection and alerts.

3. **Training:**
   - Train the security team to handle credential-based attacks, including brute force and credential stuffing.

4. **Communication Plan:**
   - Create an escalation plan for IT support and privileged account holders during incidents.
  
---

### 2️⃣ Detection & Analysis
#### Observations:

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```

![image](https://github.com/user-attachments/assets/04a4e73b-c035-4718-a225-e62d642441c0)

- **Four Azure VMs** were targeted by brute force attempts from **two public IPs**:
  
  | **Remote IP**       | **Failed Attempts** | **Target Machine**    |
  |---------------------|---------------------|-----------------------|
  | `185.243.96.107`    | 100,95,85               | `windows-10-de, 23-04-25, thvm-f`    |
  | `118.107.40.165`     | 40              | `threathuntfinal`    |


![image](https://github.com/user-attachments/assets/12730326-f068-4b42-b52c-c686102fed57)

- Query to detect Sucessful logins

```kql
DeviceLogonEvents
| where RemoteIP in ("185.243.96.107", "118.107.40.165" )
| where ActionType != "LogonFailed"
```

**Result:** No successful logins from these IPs were detected.

Analysis Steps:

1. Review Patterns:
- Investigated failed login thresholds in Azure AD logs.
- Identified off-hours timing and suspicious IP geolocations.

2. Document Findings:
- Retained logs detailing the frequency, origin, and targets of failed attempts.

3. Prioritize:
- High Priority: Privileged accounts targeted during off-hours.
- Low Priority: Isolated, user-specific failed attempts.

---

### 3️⃣ Containment
Immediate Actions:
Device Isolation:

Isolated affected devices using Microsoft Defender for Endpoint.
Network Security Group (NSG) Update:

Restricted RDP access to authorized IPs only.
Blocked all external IPs linked to failed login attempts.
Anti-Malware Scans:

Performed scans on affected devices for potential compromise.

---

### 4️⃣ Eradication & Recovery
1. **Password Reset:**
   - Reset passwords for targeted accounts.
   - Enforced strong password policies for privileged accounts.

2. **MFA Enforcement:**
   - Enabled multi-factor authentication for all high-value accounts.

3. **Geo-blocking:**
   - Blocked login attempts from high-risk geolocations.

---

### 5️⃣ Post-Incident Activity
1. **Lessons Learned:**
   - Was detection quick and effective?
   - Were privileged accounts adequately protected?

2. **System Improvements:**
   - Adjusted login thresholds for quicker detection.
   - Expanded employee training on password security.

3. **Documentation:**
   - Recorded all findings, actions taken, and future recommendations.


