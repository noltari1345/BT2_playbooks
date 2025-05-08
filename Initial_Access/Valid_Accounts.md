### **Incident Response Playbook: Valid Accounts Compromise**

#### **1. Identification**

* **Objective:** Detect the use of valid but compromised credentials to gain unauthorized access.

**Steps:**

1. **Monitor and Detect Suspicious Account Activity:**

   * Look for anomalous login patterns (e.g., unusual times, locations, or devices).
   * Identify abnormal access to sensitive systems or data.
   * Monitor for failed login attempts followed by successful ones (indicating credential stuffing).
   * Identify suspicious use of privileged accounts, especially after hours.

2. **Log Sources:**

   * **Active Directory Logs:**

     * Event ID 4624: Successful logon
     * Event ID 4625: Failed logon
     * Event ID 4768/4769: Kerberos ticket granting ticket (TGT) and service ticket request
     * Event ID 4776: Credential validation
   * **Windows Security Logs:**

     * Event ID 4672: Special privileges assigned to new logon
   * **VPN or Remote Access Logs:**

     * Identify connections from unusual geographic locations or IP addresses.
   * **SIEM Queries:**

     * Correlate login activity with known working hours.
     * Identify excessive logon failures followed by success.

3. **Indicators of Compromise (IoCs):**

   * Unfamiliar IP addresses in VPN logs or SIEM data.
   * Accounts logging in from multiple locations simultaneously.
   * High volume of authentication attempts within a short period.
   * Logins from known malicious IPs or TOR exit nodes.

4. **Detection Techniques:**

   * Monitor for the use of compromised credentials in abnormal contexts (e.g., service accounts logging in interactively).
   * Use threat intelligence feeds to identify malicious IPs and correlate with login attempts.
   * Monitor authentication methods that bypass MFA.

---

#### **2. Containment**

* **Objective:** Restrict the compromised account's access to limit further damage.

**Steps:**

1. **Account Lockdown:**

   * Immediately disable compromised accounts to prevent misuse.
   * Revoke any active session tokens or authentication tokens.
   * Force a password reset through a secure, verified channel.

2. **System Isolation:**

   * Disconnect affected systems from the network to contain potential lateral movement.
   * Quarantine endpoints associated with the compromised account.

3. **Access Revocation:**

   * Remove compromised accounts from privileged groups (e.g., Administrators, Domain Admins).
   * Reset privileged credentials for critical systems.
   * Invalidate cached or stored credentials on all affected systems.

---

#### **3. Eradication**

* **Objective:** Remove the attacker’s access and remediate vulnerabilities.

**Steps:**

1. **Credential Hygiene:**

   * Enforce password changes for affected users and service accounts.
   * Implement MFA if not already active, especially on VPN and RDP access.
   * Review and update authentication methods to reduce vulnerabilities.

2. **Audit Privileged Access:**

   * Identify all accounts with elevated permissions and audit recent activity.
   * Rotate passwords for service accounts that may have been compromised.

3. **Remove Malicious Persistence:**

   * Check for new or modified scheduled tasks and services that run under compromised accounts.
   * Inspect any abnormal group policy changes made with the compromised account.
   * Remove any newly created or modified backdoor accounts.

---

#### **4. Recovery**

* **Objective:** Restore normal operations and ensure ongoing security.

**Steps:**

1. **Revalidate User Accounts:**

   * Verify that all password resets have been successful.
   * Educate users on safe credential practices to avoid reuse of compromised credentials.

2. **System Integrity Check:**

   * Conduct a thorough scan for malware or persistence mechanisms on affected systems.
   * Apply security patches to address exploited vulnerabilities.

3. **Monitor for Recurrence:**

   * Set up alerts for new logon attempts from suspicious IPs.
   * Implement continuous monitoring for privilege escalation or lateral movement.
   * Utilize honeypots or canary accounts to detect post-recovery abuse.

---

#### **5. Lessons Learned**

* **Objective:** Analyze the incident to improve future responses.

**Steps:**

1. **Incident Debrief:**

   * Document the timeline of the incident and response.
   * Identify gaps in credential management or monitoring.
   * Determine how the account was compromised (phishing, password reuse, brute force).

2. **Security Policy Update:**

   * Enforce stronger password policies (length, complexity, rotation).
   * Mandate MFA for all privileged accounts and remote access.
   * Implement geofencing to block logins from high-risk regions.

3. **Awareness and Training:**

   * Conduct training sessions on phishing awareness and credential security.
   * Emphasize the importance of using unique and strong passwords.

4. **Improved Monitoring:**

   * Enhance SIEM alerts to detect account anomalies (e.g., logins from unusual locations).
   * Use behavioral analytics to flag deviations from normal usage patterns.

