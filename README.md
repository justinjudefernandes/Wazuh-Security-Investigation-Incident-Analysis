# Wazuh Security Investigation & Incident Analysis

## 🎯 Objective:
Investigate suspicious Windows and Linux activity using Wazuh telemetry by correlating account manipulation, privilege changes, authentication activity, potential lateral movement, and file integrity events to reconstruct the attack timeline, identify indicators, assess impact, and develop response recommendations.

## 🕵️ Findings:
The investigation identified suspicious activities affecting both Windows and Linux systems. The observed activities included unauthorized account management actions, SSH authentication attempts, and file modifications and deletions detected through endpoint and file integrity monitoring.

The following findings were identified:
- The built-in Guest account was enabled.
- A new Windows local account (student1) was created.
- The student1 account was added to the local Administrators group, granting elevated privileges.
- The student1 account was subsequently deleted.
- Multiple failed SSH authentication attempts were observed against the Linux server (192.168.126.164) using the fakeuser account, indicating potential lateral movement from the Windows endpoint (192.168.126.165).
- A successful SSH authentication was observed using the mydfir account, indicating lateral movement from the Windows endpoint to the Linux server.
- Monitored files on both Windows and Linux were modified and subsequently deleted.

### 🔍 Evidence 1 – Guest Account Enabled (Event ID 4722)

<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/8ce024bd-6fc3-45b3-92f4-9b0a1a3ae8f2" />
<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/93acc975-af67-45b0-8330-9e5cd5eda777" />

### 🔍 Evidence 2 – Windows User Account Created (Event ID 4720)

<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/a5457e12-9ae2-423e-bcfa-193e890cf917" />
<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/d65fa36b-3f3c-41a8-9e5b-83ad9ea002af" />

### 🔍 Evidence 3 – User Added to Local Administrators Group (Event ID 4732)

<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/e67898b7-2c8b-4ba3-bd3f-3d200c37cc4e" />
<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/9bd7c859-9cc2-4ab9-8320-50a3b55d2160" />

### 🔍 Evidence 4 – User Account Deleted (Event ID 4726)

<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/3d971cef-8e37-4f44-823d-21844c302496" />
<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/bf3b3ff8-80c8-4f1c-a8c2-5274f1840f24" />

### 🔍 Evidence 5 – Failed SSH Authentication Attempts (search: fakeuser)

<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/9ce80e85-3534-4fba-bfc9-e573e512d9ae" />
<img width="390" height="230" alt="image" src="https://github.com/user-attachments/assets/b46e69ee-b504-4f3a-89d1-3e0fa5708bb0" />

### 🔍 Evidence 6 – Successful SSH Authentication (search: mydfir AND accepted)

<img width="785" height="450" alt="image" src="https://github.com/user-attachments/assets/8566ca37-914e-4da7-8fcf-1208b4dfe87e" />

### 🔍 Evidence 7 – Windows File Modification & Deletion Event

<img width="785" height="450" alt="image" src="https://github.com/user-attachments/assets/9e72dbd4-3012-4818-a120-b6287b79281c" />

### 🔍 Evidence 8 – Linux File Modification & Deletion Event

<img width="785" height="450" alt="image" src="https://github.com/user-attachments/assets/47fa3775-2c7d-4947-bd28-37cc012caaf6" />


## 📋 Investigation Summary:
The investigation identified suspicious activities involving Windows account management, Linux SSH authentication, and file integrity events across the Windows and Linux systems.

The activity began on the Windows endpoint with the Guest account being enabled. Shortly afterward, a local user account named student1 was created, added to the local Administrators group, and subsequently deleted. These events indicate that a new account was created, granted elevated privileges, and later removed.

The investigation then identified SSH authentication activity against the Linux server. Multiple failed SSH authentication attempts using the fakeuser account were observed from the Windows endpoint, followed by a successful SSH authentication using the mydfir account. This activity is consistent with potential lateral movement from the Windows endpoint to the Linux server. 

Subsequently, file integrity events were observed on both systems. Monitored files on the Windows endpoint were modified and subsequently deleted, followed by similar modification and deletion activity on the Linux server. This indicates that monitored files on both operating systems were altered during the investigation period.

Based on the available evidence, the observed sequence of events is consistent with suspicious account manipulation, potential lateral movement, and subsequent file modification and deletion activity across the Windows and Linux environments.

### 🧐 Triage (5W & 1H):
#### WHO:
```KQL query
•	Hosts Involved:
    o  Windows 10 Endpoint
    o  Ubuntu 24.04 Linux Server
    o  Wazuh Monitoring Infrastructure
•	Accounts Involved:
    o  Windows:
        *  student1 (Created, Added to Administrators, Deleted)
        *  Guest (Enabled)
    o  	Linux:
        *  fakeuser (Failed SSH authentication attempts)
        *  mydfir (Successful SSH authentication)
```

#### WHAT:
```KQL query
•	Enabling of the built-in Guest account.
•	Creation of a new Windows local user account (student1).
•	Addition of student1 to the local Administrators group.
•	Deletion of the student1 account.
•	Multiple failed SSH authentication attempts against the Linux server from the Windows endpoint using the fakeuser account.
•	Successful SSH authentication to the Linux server using the mydfir account.
•	Modification of monitored files on the Windows and Linux systems.
•	Subsequent deletion of the monitored files.
```

#### WHEN:
```KQL query
•	Aug 5, 2026 @ 09:04:19 AM: Enabled the built-in Guest account.
•	Aug 5, 2026 @ 09:10:52 AM: Created the student1 Windows local account.
•	Aug 5, 2026 @ 09:11:11 AM: Added to the Administrators group.
•	Aug 5, 2026 @ 09:11:33 AM: The student1 account was subsequently deleted.
•	Aug 5, 2026 @ 10:24:59 AM - 10:25:17 AM: Multiple failed SSH attempts using fakeuser were observed against the Linux server (192.168.126.164), indicating lateral movement from the Windows endpoint (192.168.126.165).
•	Aug 5, 2026 @ 10:53:57 AM: A successful SSH login using mydfir was observed, indicating lateral movement from the Windows endpoint.
•	Monitored files on Windows and Linux were modified and subsequently deleted.
        o Windows - Aug 6, 2026 @ 11:21:13 AM
        o Linux - Aug 6, 2026 @ 11:50:49 AM

```

#### WHERE:
```KQL query
Windows Endpoint:
    o	Windows Security Event Logs
    o	Local Security Accounts Manager (SAM)
    o	C:\CompanyData
Linux Server:
    o	SSH Service
    o	Linux Authentication Logs
    o	/opt/company-data

```

#### WHY:
```KQL query
•	Establishing a privileged local account.
•	Enabling an existing account for potential access or persistence.
•	Attempting remote access to the Linux server through SSH.
•	Potential lateral movement from the Windows endpoint to the Linux server.
•	Modifying and deleting monitored files, potentially to alter or remove evidence.
```

#### HOW:
```KQL query
•	Windows account manipulation using local account management to enable Guest, create student1, grant administrative privileges, and delete the account.
•	SSH-based remote access from the Windows endpoint to the Linux server, using fakeuser for failed authentication attempts and mydfir for successful authentication.
•	File system activity on monitored Windows and Linux directories, where files were modified and subsequently deleted.
```

## 🛑 Response Actions Performed:
- Reviewed Windows account management events to establish the sequence of Guest account enablement, student1 account creation, administrative privilege assignment, and account deletion.
- Analyzed Windows and Linux authentication logs to identify failed and successful SSH authentication activity.
- Correlated the SSH activity between the Windows endpoint (192.168.126.165) and Linux server (192.168.126.164) to identify potential lateral movement.
- Reviewed file integrity events to identify monitored files that were modified and subsequently deleted on both systems.
- Correlated account, authentication, and file integrity events to establish the overall investigation timeline.
- Documented the identified activities and associated evidence for further validation and follow-up.

## 💡 Recommendations:
- Confirm whether the Guest account enablement and student1 account activity were authorized. Disable or remove accounts that are not required.
- Validate the mydfir SSH authentication with the account owner and investigate the failed 'fakeuser' authentication attempts.
- Review the affected Windows and Linux files and restore any required data from known-good backups.
- Review privileged account memberships and implement regular access reviews.
- Restrict SSH access to authorized administrative sources and accounts where operationally feasible.
- Expand file integrity monitoring to additional critical systems, files, and directories.
- Continue monitoring the affected systems for any further unauthorized account, authentication, or file activity.

## 🧠 Security Operations Takeaways:
- **_Event correlation is critical:_** Individual account, authentication, or file events may appear benign, but their correlation can reveal a broader attack sequence.
- **_Temporary privileged accounts require visibility:_** Short-lived accounts that are created, elevated, and deleted can indicate suspicious activity and should receive increased monitoring.
- **_Built-in accounts require monitoring:_** Changes to accounts such as Guest should generate visibility because they can introduce additional access paths.
- **_Authentication monitoring provides lateral movement visibility:_** Correlating source and destination systems with SSH authentication events can help identify potential movement between hosts.
- **_File integrity monitoring adds valuable context:_** File modifications and deletions can provide important evidence when correlated with preceding authentication or account activity.
- **_Detection should focus on behavior chains:_** Combining multiple related events into a single detection or investigation provides better visibility than monitoring each event independently.

