### **Incident Response Playbook: Phishing on a Windows Enterprise Network**

#### **1. Identification**

* **Objective:** Detect and verify phishing attempts targeting employees or systems within the enterprise.

**Steps:**

1. **Monitor and Detect Suspicious Emails:**

   * Look for emails from unfamiliar or suspicious domains.
   * Identify emails with attachments, especially with unusual file extensions (`.zip`, `.exe`, `.js`, `.docm`).
   * Detect links with encoded URLs or unusual redirect patterns.
   * Check for emails with urgent language (e.g., “Immediate Action Required!”).

2. **Log Sources:**

   * **Email Gateway Logs:**

     * Blocked or flagged emails.
     * Spam and phishing email logs.
   * **Endpoint Security Logs:**

     * Malware detections linked to email attachments.
   * **SIEM Data:**

     * Correlate email events with login attempts from new locations.
   * **Active Directory Logs:**

     * Event ID 4624: Successful logon
     * Event ID 4625: Failed logon
   * **DNS Logs:**

     * Look for DNS queries to suspicious domains (often associated with phishing sites).

3. **Indicators of Compromise (IoCs):**

   * Malicious email addresses, domains, or IPs.
   * Hashes of malicious attachments or scripts.
   * Command-line activity related to file execution from email attachments.
   * HTTP/HTTPS requests to phishing domains.

4. **Detection Techniques:**

   * **SIEM Rules:**

     * Identify sudden increases in email reports from users.
     * Correlate phishing indicators with recent login attempts.
   * **Content Inspection:**

     * Analyze the email body and attachments for phishing signatures.
   * **URL Analysis:**

     * Use threat intelligence feeds to check links within emails.
   * **User Reports:**

     * Encourage employees to report suspicious emails.

---

#### **2. Containment**

* **Objective:** Prevent the spread and minimize the impact of phishing attacks.

**Steps:**

1. **Block and Quarantine:**

   * Use the email gateway to block the sender’s domain or IP.
   * Quarantine emails matching the phishing pattern.
   * Use DNS filtering to block phishing domains.

2. **Account Containment:**

   * Immediately disable any compromised accounts.
   * Reset passwords and force MFA re-enrollment for affected users.
   * Revoke OAuth tokens or app authorizations granted through phishing links.

3. **Endpoint Isolation:**

   * Disconnect affected systems from the network.
   * Isolate endpoints showing signs of credential theft or malware execution.

4. **Communication and User Awareness:**

   * Inform employees of the phishing attempt.
   * Instruct users not to open similar emails or click on links.
   * Provide a secure channel to report suspicious emails.

---

#### **3. Eradication**

* **Objective:** Remove phishing artifacts and ensure no residual threats remain.

**Steps:**

1. **Email Cleanup:**

   * Search for similar phishing emails within the organization.
   * Delete any identified malicious emails from mailboxes.

2. **Scan Compromised Endpoints:**

   * Perform a full malware scan on impacted systems.
   * Search for credential stealers (e.g., Mimikatz) and keyloggers.
   * Use forensic tools to identify malware persistence mechanisms.

3. **Credential Hygiene:**

   * Reset passwords for all potentially compromised accounts.
   * Invalidate any cached credentials on affected endpoints.
   * Revoke tokens associated with the compromised accounts.

4. **Remove Malicious Content:**

   * Delete any downloaded phishing files or scripts.
   * Remove browser extensions installed during phishing attacks.
   * Clean up scheduled tasks created by phishing payloads.

---

#### **4. Recovery**

* **Objective:** Safely restore normal operations and prevent further incidents.

**Steps:**

1. **User Education:**

   * Conduct a brief refresher on phishing awareness.
   * Share key indicators of phishing attempts with users.

2. **Credential Update:**

   * Force organization-wide password changes if phishing was widespread.
   * Implement MFA on all accounts, especially privileged ones.

3. **Patch and Harden Systems:**

   * Apply security patches for any exploited vulnerabilities.
   * Harden email filtering rules to block future phishing attempts.

4. **Monitor for Recurrence:**

   * Set up SIEM alerts for similar phishing patterns.
   * Track login attempts from unusual IP addresses or geolocations.
   * Continuously monitor for malware beaconing or C2 communication.

---

#### **5. Lessons Learned**

* **Objective:** Improve phishing resilience and prepare for similar future incidents.

**Steps:**

1. **Post-Incident Review:**

   * Identify why the phishing email bypassed filtering mechanisms.
   * Determine the effectiveness of user reporting and response.
   * Analyze why certain accounts or systems were more vulnerable.

2. **Strengthen Email Security:**

   * Implement DMARC, SPF, and DKIM to reduce email spoofing.
   * Enable advanced anti-phishing features in the email gateway.
   * Conduct regular phishing simulation tests to gauge employee readiness.

3. **Policy Improvement:**

   * Update the incident response plan to address phishing-specific scenarios.
   * Enforce stricter email filtering and link scanning policies.
   * Regularly review and update phishing detection signatures.

4. **Training and Awareness:**

   * Conduct phishing awareness training at least quarterly.
   * Distribute a one-page guide on recognizing phishing indicators.
   * Involve the IT help desk in reporting workflows to streamline response.

