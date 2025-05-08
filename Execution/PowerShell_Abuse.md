### **Incident Response Playbook: PowerShell Abuse**

#### **1. Identification**

* **Objective:** Detect malicious or suspicious use of PowerShell within the network.

**Steps:**

1. **Monitor and detect abnormal PowerShell activity:**

   * Check for unusual process creation using PowerShell (e.g., `powershell.exe`, `pwsh.exe`).
   * Look for encoded or obfuscated commands (e.g., `-encodedcommand`).
   * Identify long or suspicious command lines (e.g., Base64 encoded payloads).
   * Monitor the creation of unusual child processes (e.g., PowerShell spawning CMD or WMI).

2. **Log Sources:**

   * **Windows Event Logs:**

     * Event ID 4104: Script Block Logging
     * Event ID 4688: Process Creation
     * Event ID 4103: Module Logging
   * **Sysmon Logs:**

     * Event ID 1: Process Creation
   * **EDR/AV Alerts:** Suspicious PowerShell activity or memory injections.
   * **SIEM Queries:**

     * Search for base64 strings in command-line arguments.
     * Identify processes with parent-child relationships involving PowerShell.

3. **Indicators of Compromise (IoCs):**

   * Encoded commands or base64 strings.
   * Unusual network connections initiated by PowerShell.
   * PowerShell scripts running from non-standard directories.
   * Scripts with suspicious keywords (`iex`, `Invoke-Expression`, `New-Object Net.WebClient`).

---

#### **2. Containment**

* **Objective:** Isolate affected systems and mitigate further impact.

**Steps:**

1. **Isolate Compromised Hosts:**

   * Disconnect affected systems from the network to prevent lateral movement.
   * Quarantine hosts showing active malicious PowerShell usage.

2. **Block Malicious Scripts:**

   * Restrict execution of suspicious PowerShell scripts.
   * Block known malicious scripts and hashes using endpoint protection tools.

3. **Disable Unnecessary PowerShell Features:**

   * Set the PowerShell execution policy to `Restricted` or `AllSigned`.
   * Disable PowerShell remoting (`Disable-PSRemoting`).

4. **Revoke Compromised Credentials:**

   * Reset accounts that executed the malicious PowerShell commands.
   * Invalidate authentication tokens if possible.

---

#### **3. Eradication**

* **Objective:** Remove malicious scripts and restore system integrity.

**Steps:**

1. **Script and File Removal:**

   * Identify and delete all instances of malicious scripts.
   * Clean temporary directories (e.g., `%TEMP%`, `%APPDATA%`).

2. **Reinforce PowerShell Logging:**

   * Enable PowerShell Script Block Logging for future detection.
   * Implement Module Logging to track script execution.

3. **Patch and Update:**

   * Apply security updates for PowerShell and Windows OS.
   * Update antivirus/EDR signatures to detect similar threats.

---

#### **4. Recovery**

* **Objective:** Safely restore operations and ensure system integrity.

**Steps:**

1. **System Restoration:**

   * Restore affected systems from clean backups if compromise is severe.
   * Rebuild systems from a known-good image if integrity cannot be assured.

2. **Credential Hygiene:**

   * Rotate all affected passwords and invalidate cached credentials.
   * Implement multi-factor authentication (MFA) for critical accounts.

3. **Monitor Post-Recovery:**

   * Set up alerts for unusual PowerShell usage in SIEM.
   * Continuously monitor high-value systems and user accounts.

---

#### **5. Lessons Learned**

* **Objective:** Improve defensive measures and prevent recurrence.

**Steps:**

1. **Incident Debrief:**

   * Document the attack vector and PowerShell techniques used.
   * Identify gaps in detection and response capabilities.

2. **Policy and Configuration Adjustments:**

   * Implement application whitelisting for PowerShell.
   * Restrict execution policy on critical servers.

3. **Training and Awareness:**

   * Educate staff on recognizing and reporting abnormal PowerShell usage.
   * Train incident responders on detecting PowerShell-based attacks.

---
