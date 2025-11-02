# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/rmalavad/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to own TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze lated security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or related file creation.
- **Check `DeviceProcessEvents`** for signs of installation or execution.
- **Check `DeviceNetworkEvents`** for any outgoing connections to known TOR ports or nodes.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Queried for any file names containing “tor” on the suspected endpoint `threat-hunt-lab`.  
Results revealed that user **employee** downloaded a TOR installer and extracted its contents to the Desktop, including several TOR-related binaries and a text file named **tor-shopping-list.t**.

**Query used to locate events:**
```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "employee"
| where Timestamp >= datetime(2025-10-06T22:50:19.0811462Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```

**Key Finding:**  
At `2025-10-07T00:02:48.8880577Z`, the user created `tor-shopping-list.txt` on the Desktop.  
TOR-related executables and folders were copied starting around `2025-10-06T22:50:19Z`.

**[📁 View Evidence: tor-download.csv](https://drive.google.com/file/d/1luCUsCBv6WzWYsu9LluZ6WJ4XzwFAEZU/view?usp=sharing)**

---

### 2. Searched the `DeviceProcessEvents` Table

Checked for any `ProcessCommandLine` instances containing the TOR installer filename.  
Logs showed that user **employee** executed **tor-browser-windows-x86_64-portable-14.5.7.exe** from the Downloads folder at `2025-10-06T23:52:01.333Z`.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

**Key Finding:**  
TOR browser installer executed manually by the user, initiating extraction and installation.

**[📁 View Evidence: tor-install.csv](https://drive.google.com/file/d/1eTfJj_imun5BFfbNfDXU5sDNY7aF2Ogj/view?usp=sharing)**

---

### 3. Verified TOR Execution via `DeviceProcessEvents`

Queried for any evidence of the actual TOR browser running post-installation.  
Found that **tor.exe** launched from the Desktop installation directory, indicating active use of the browser.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

**Key Finding:**  
Execution of `tor.exe` confirmed at `2025-10-06T23:55:35.338Z`, indicating the browser was launched successfully.

**[📁 View Evidence: tor-process-creation.csv](https://drive.google.com/file/d/1suz99BAwGZT8z6lhsWWSg1HbPbeZTnkz/view?usp=sharing)**

---

### 4. Checked `DeviceNetworkEvents` for TOR Connections

Searched for outbound connections initiated by **tor.exe** over known TOR ports.  
Detected successful connections to external IP addresses over **port 9001**, as well as encrypted traffic over **port 443**.

**Query used to locate events:**
```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "employee"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

**Key Findings:**  
- `2025-10-06T23:55:35Z` → Connection to **51.178.131.200:9001** (TOR relay node).  
- Additional encrypted connections observed over **port 443**, confirming active TOR session establishment.

**[📁 View Evidence: tor-usage.csv](https://drive.google.com/file/d/1PGRHJ88R-kzrynWBQQ1PAPwyYDcRnoZI/view?usp=sharing)**

---

## Chronological Event Timeline

### 1. File Download – TOR Installer
- **Timestamp:** `2025-10-06T22:50:19.081Z`  
- **Event:** User “employee” downloaded `tor-browser-windows-x86_64-portable-14.5.7.exe` to the Downloads folder.  
- **Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.7.exe`  
- **Action:** File creation event recorded.

### 2. Process Execution – TOR Installation
- **Timestamp:** `2025-10-06T23:52:01.333Z`  
- **Event:** Execution of TOR browser installer initiated.  
- **Action:** Process creation detected.  
- **Command:** `tor-browser-windows-x86_64-portable-14.5.7.exe /S`  
- **Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.7.exe`

### 3. Process Execution – TOR Browser Launch
- **Timestamp:** `2025-10-06T23:55:35.338Z`  
- **Event:** TOR browser (`tor.exe`) executed from Desktop path.  
- **Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  
- **Action:** TOR process execution confirmed.

### 4. Network Connection – TOR Node
- **Timestamp:** `2025-10-06T23:55:35.338Z`  
- **Event:** Connection established to **51.178.131.200** on **port 9001** via `tor.exe`.  
- **Action:** Connection success.  
- **Process:** `tor.exe`  
- **Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Connections – Encrypted Traffic
- **Timestamp:** `2025-10-06T23:55:45Z`  
- **Event:** Additional connections over **port 443** to multiple IPs.  
- **Action:** Successful encrypted outbound traffic observed.  
- **Note:** Indicates full TOR circuit establishment and browsing session.

### 6. File Creation – “tor-shopping-list.txt”
- **Timestamp:** `2025-10-07T00:02:48.888Z`  
- **Event:** Creation of `tor-shopping-list.txt` on Desktop.  
- **Action:** File creation confirmed.  
- **Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

User **employee** on endpoint **threat-hunt-lab** downloaded, installed, and executed the TOR browser, subsequently connecting to multiple external IPs associated with TOR entry nodes.  
The timeline of events, combined with file creation artifacts (e.g., `tor-shopping-list.txt`), strongly confirms intentional TOR usage for anonymous web access.

This activity bypassed standard web filtering policies and established encrypted tunnels to external TOR nodes, constituting a policy violation and potential security risk.

---

## Response Taken

- TOR browser usage was confirmed on the endpoint `threat-hunt-lab`.  
- Device was immediately **isolated** from the network.  
- User’s direct manager and the security operations lead were notified.  
- Follow-up actions included revoking local admin privileges and reinforcing **acceptable use policies** across all workstations.

---
