# Wazuh Security Investigation & Incident Analysis

## Findings:
The investigation identified suspicious activities affecting both Windows and Linux systems. The observed activities included unauthorized account management actions, SSH authentication attempts, and file modifications and deletions detected through endpoint and file integrity monitoring.

The following findings were identified:
- The built-in Guest account was enabled.
- A new Windows local account (student1) was created.
- The student1 account was added to the local Administrators group, granting elevated privileges.
- The student1 account was subsequently deleted.
- Multiple failed SSH authentication attempts were observed against the Linux server (192.168.126.164) using the fakeuser account, indicating potential lateral movement from the Windows endpoint (192.168.126.165).
- A successful SSH authentication was observed using the mydfir account, indicating lateral movement from the Windows endpoint to the Linux server.
- Monitored files on both Windows and Linux were modified and subsequently deleted.


### 🔍 Evidence 1 – Guest Account Enabled

### 🔍 Evidence 2 – Windows User Account Created (Event ID 4720)

### 🔍 Evidence 3 – User Added to Local Administrators Group (Event ID 4732)

### 🔍 Evidence 4 – User Account Deleted (Event ID 4726)

### 🔍 Evidence 5 – Failed SSH Authentication Attempts

### 🔍 Evidence 6 – Successful SSH Authentication

### 🔍 Evidence 7 – Windows File Modification & Deletion Event

### 🔍 Evidence 8 – Linux File Modification & Deletion Event


## Investigation Summary:
The investigation identified suspicious activities involving Windows account management, Linux SSH authentication, and file integrity events across the Windows and Linux systems.

The activity began on the Windows endpoint with the Guest account being enabled. Shortly afterward, a local user account named student1 was created, added to the local Administrators group, and subsequently deleted. These events indicate that a new account was created, granted elevated privileges, and later removed.

The investigation then identified SSH authentication activity against the Linux server. Multiple failed SSH authentication attempts using the fakeuser account were observed from the Windows endpoint, followed by a successful SSH authentication using the mydfir account. This activity is consistent with potential lateral movement from the Windows endpoint to the Linux server. 

Subsequently, file integrity events were observed on both systems. Monitored files on the Windows endpoint were modified and subsequently deleted, followed by similar modification and deletion activity on the Linux server. This indicates that monitored files on both operating systems were altered during the investigation period.

Based on the available evidence, the observed sequence of events is consistent with suspicious account manipulation, potential lateral movement, and subsequent file modification and deletion activity across the Windows and Linux environments.

### Triage (5W & 1H)
#### WHO:
```KQL query
Hosts Involved:
  - Windows 10 Endpoint
  - Ubuntu 24.04 Linux Server
  - Wazuh Monitoring Infrastructure
Accounts Involved:
  - Windows:
    - student1 (Created, Added to Administrators, Deleted)
    -	Guest (Enabled)
  - Linux:
    -	fakeuser (Failed SSH authentication attempts)
    -	mydfir (Successful SSH authentication)

```

#### WHAT:
```KQL query

```

#### WHEN:
```KQL query

```

#### WHERE:
```KQL query

```

#### WHY:
```KQL query

```

#### HOW:
```KQL query

```

## 🛑 Response Actions:


## 💡 Recommendations:


## 🧠 Lessons Learned:


