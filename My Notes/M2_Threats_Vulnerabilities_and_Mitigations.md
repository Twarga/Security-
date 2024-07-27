# Summary: Threats, Vulnerabilities, and Mitigations

## **1. Comparison of Common Threat Actors and Motivations**

**Threat Actors:**
- **Nation-State:** Government-affiliated entities with advanced resources and technologies aiming for espionage, warfare, or political influence.
- **Unskilled Attacker:** Individuals with basic technical skills pursuing curiosity, fame, or learning.
- **Hacktivist:** Activists using hacking for political or social causes to bring attention to issues.
- **Insider Threat:** Employees or individuals within an organization who misuse their access for revenge, financial gain, or negligence.
- **Organized Crime:** Criminal groups using cyber techniques for financial gain, blackmail, or theft.
- **Shadow IT:** Unauthorized technology use within an organization to bypass security policies or inefficiencies.

**Attributes of Actors:**
- **Internal vs External:** Internal actors misuse legitimate access, while external actors must breach defenses to access systems.
- **Resource/Funding:** High-resource actors include nation-states and organized crime, while low-resource actors like unskilled attackers have fewer means.
- **Sophistication:** Nation-states and organized crime often use advanced techniques, while less sophisticated attackers use simpler methods.

**Motivations:**
- **Data Exfiltration:** Stealing sensitive information.
- **Espionage:** Gaining strategic advantages.
- **Service Disruption:** Causing operational issues.
- **Blackmail:** Extorting individuals or organizations.
- **Financial Gain:** Engaging in cyber activities for profit.
- **Philosophical/Political Beliefs:** Promoting a cause or disrupting injustices.
- **Ethical:** Exposing security flaws for improvement.
- **Revenge:** Acting out of personal grudges.
- **Disruption/Chaos:** Creating confusion or instability.
- **War:** Conducting cyber operations as part of a conflict.

## **2. Common Threat Vectors and Attack Surfaces**

**Message-Based:**
- **Email:** Used for phishing and malware delivery.
- **SMS:** Exploited for smishing and malicious links.
- **Instant Messaging:** Vulnerable to malware and phishing.

**Image-Based:**
- **Images:** Can hide malicious code or exploit vulnerabilities in processing software.

**File-Based:**
- **Files:** Contain malware or exploit vulnerabilities.

**Voice Call Based:**
- **Voice Communication:** Used for social engineering attacks.

**Removable Device:**
- **External Storage:** Introduces malware or steals data.

**Vulnerable Software:**
- **Client-Based:** Exploitable software on client devices.
- **Agentless:** Remote software vulnerabilities.

**Unsupported Systems and Applications:**
- **Outdated Systems:** Exploited due to lack of updates.

**Unsecure Networks:**
- **Wireless:** Intercepted or compromised Wi-Fi.
- **Wired:** Vulnerable physical network connections.
- **Bluetooth:** Short-range communication vulnerabilities.

**Open Service Ports:**
- **Open Ports:** Exploited for unauthorized access.

**Default Credentials:**
- **Default Settings:** Exploited due to lack of configuration changes.

**Supply Chain:**
- **Managed Service Providers (MSPs):** Compromises affect all clients.
- **Vendors:** Vulnerabilities in third-party products.
- **Suppliers:** Malicious components from physical suppliers.

**Human Vectors/Social Engineering:**
- **Phishing:** Fraudulent attempts for sensitive information.
- **Vishing:** Voice-based phishing.
- **Smishing:** SMS-based phishing.
- **Misinformation/Disinformation:** Spreading false information.
- **Impersonation:** Pretending to be someone else for unauthorized access.
- **Business Email Compromise (BEC):** Fraud targeting business email.
- **Pretexting:** Fabricated scenarios for information.
- **Watering Hole:** Compromising frequently visited websites.
- **Brand Impersonation:** Deceiving with fake brands.
- **Typosquatting:** Using misspelled domains for phishing.

## **3. Types of Vulnerabilities**

**Application:**
- **Memory Injection:** Malicious code in application memory.
- **Buffer Overflow:** Corrupts adjacent memory by exceeding buffer limits.
- **Race Conditions:** Issues with simultaneous process access.
  - **TOC:** Condition checked separately from action.
  - **TOU:** Condition checked and acted upon in a time-sensitive manner.
- **Malicious Update:** Updates with malicious code.

**Operating System (OS)-Based:**
- **Vulnerabilities:** Exploited due to outdated patches or misconfigurations.

**Web Based:**
- **SQL Injection (SQLi):** Arbitrary SQL queries in a database.
- **Cross-Site Scripting (XSS):** Injecting malicious scripts into web pages.

**Hardware:**
- **Firmware:** Vulnerabilities in hardware firmware.
- **End-of-Life:** Unsupported hardware with security risks.
- **Legacy:** Older hardware lacking modern security features.

**Virtualization:**
- **VM Escape:** Attacker accesses host or other VMs.
- **Resource Reuse:** Exploiting shared VM resources.

**Cloud-Specific:**
- **Vulnerabilities:** Misconfigurations and security flaws in cloud services.

**Supply Chain:**
- **Service Provider:** Vulnerabilities in third-party IT services.
- **Hardware Provider:** Vulnerabilities in third-party hardware components.
- **Software Provider:** Vulnerabilities in third-party software.

**Cryptographic:**
- **Vulnerabilities:** Weak encryption or outdated algorithms.

**Misconfiguration:**
- **Security Issues:** Incorrect system, network, or application configurations.

**Mobile Device:**
- **Side Loading:** Installing apps from unofficial sources.
- **Jailbreaking:** Removing OS restrictions to install unauthorized apps.
- **Zero-Day:** Unknown vulnerabilities without available fixes.

## **4. Analyzing Indicators of Malicious Activity**

**Malware:**
- **Amplified:** Malware using amplification techniques.
- **Birthday:** Exploits related to hash collisions.
- **Ransomware:** Encrypts files, demanding ransom.
- **Reflected:** Attacks reflecting malicious payloads.

**Password Attacks:**
- **Brute Force:** Attempting all possible combinations.
- **DNS Spraying:** Brute force on DNS.
- **Credential Replay:** Using stolen credentials.
- **Password Spraying:** Common passwords tried across accounts.

**Worm Attacks:**
- **Self-Replicating Malware:** Spreads rapidly across networks.

**Spyware:**
- **Monitoring Malware:** Collects user information.

**Keylogger:**
- **Records Keystrokes:** Captures sensitive information.

**Virus:**
- **Attaches to Files:** Spreads when infected files are executed.

**Rootkit:**
- **Maintains Stealth:** Unauthorized access with hidden files.

**Logic Bomb:**
- **Triggered Malicious Code:** Executes under specific conditions.

**Application Attacks:**
- **Injection:** Malicious code in applications.
- **Resource Consumption:** Exhausts system resources.
- **Directory Traversal:** Unauthorized directory access.

**Physical Attacks:**
- **RFID Cloning:** Cloning RFID tags.
- **Environmental:** Exploiting physical environmental conditions.
## **5. Purpose of Mitigation Techniques Used to Secure The Enterprise**

### 1. Segmentation
- **Purpose:** Divide a network into smaller, isolated segments to limit the spread of attacks and reduce the impact of a security breach.
- **Benefits:** Enhances security by controlling traffic between segments, improving containment and response to threats.

### 2. Access Control
- **Purpose:** Regulate who can access resources and what actions they can perform to protect sensitive information and systems.

  a. Access Control List (ACL)
    - **Description:** A list defining permissions for different users or groups on a network or system resource.
    - **Benefits:** Provides granular control over access permissions, helping enforce security policies.

  b. Permissions
    - **Description:** Specifies the level of access granted to users or groups (read, write, execute).
    - **Benefits:** Ensures users have only the necessary access required for their role, reducing the risk of unauthorized access.


### 3. Application Allow List
- **Purpose:** Restrict the execution of only approved applications on a system.
- **Benefits:** Prevents unauthorized or potentially malicious applications from running, reducing the risk of malware and unauthorized activities.

### 4. Isolation
- **Purpose:** Separate systems, processes, or environments to prevent interference and limit the impact of security incidents.
- **Benefits:** Protects critical systems from being affected by less secure components, enhancing overall security.

### 5. Patching
- **Purpose:** Apply updates and fixes to software and systems to address known vulnerabilities.
- **Benefits:** Reduces the risk of exploitation by closing security gaps and ensuring that systems are up-to-date with the latest security patches.

### 6. Encryption
- **Purpose:** Protect data by converting it into a secure format that is unreadable without the appropriate decryption key.
- **Benefits:** Ensures data confidentiality and integrity, making it inaccessible to unauthorized users.

### 7. Monitoring

- **Purpose:** Continuously observe and analyze systems, networks, and activities to detect and respond to security threats.
- **Benefits:** Provides visibility into security events, enabling timely detection of anomalies and prompt response to incidents.

### 8. Least Privilege
- **Purpose:** Grant users and systems the minimum level of access necessary to perform their functions.
- **Benefits:** Minimizes the risk of accidental or malicious misuse of privileges, reducing potential damage from compromised accounts.

### 9. Configuration Enforcement
- **Purpose:** Ensure that systems and applications are configured according to security best practices and policies.
- **Benefits:** Helps maintain a secure baseline, reducing vulnerabilities associated with misconfigured systems.

### 10. Decommissioning
- **Purpose:** Properly retire and remove obsolete or unneeded systems and applications.
- **Benefits:** Reduces the attack surface by eliminating outdated or unsupported components that may be vulnerable.

### 11. Hardening Techniques
- **Purpose:** Implement measures to strengthen the security of systems and applications.

    a. Encryption
        - **Description:** Use encryption to protect sensitive data at rest and in transit.
        - **Benefits:** Ensures data confidentiality and integrity.

    b. Installation of Endpoint Protection
        - **Description:** Deploy security solutions like antivirus and anti-malware on endpoints.
        - **Benefits:** Provides protection against malicious software and unauthorized access.

    c. Host-Based Firewall
        - **Description:** Implement a firewall on individual hosts to control incoming and outgoing traffic.
        - **Benefits:** Helps protect against unauthorized access and network-based attacks.

    d. Host-Based Intrusion Prevention System (HIPS)
        - **Description:** Deploy a system that monitors and responds to suspicious activities on a host.
        - **Benefits:** Detects and prevents potential intrusions based on activity patterns.

    e. Disabling Ports/Protocols
        - **Description:** Turn off unused ports and protocols to reduce potential entry points for attacks.
        - **Benefits:** Minimizes the attack surface by closing unnecessary communication channels.

    f. Default Password Changes
        - **Description:** Replace default passwords with strong, unique passwords.
        - **Benefits:** Prevents attackers from exploiting default credentials to gain unauthorized access.

    g. Removal of Unnecessary Software
        - **Description:** Uninstall software that is not needed for the system’s function.
        - **Benefits:** Reduces potential vulnerabilities and attack vectors associated with unused software.

    ---
