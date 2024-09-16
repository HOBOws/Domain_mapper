# Domain_Mapper: A Multi-Level Domain Scanning Script

Domain_Mapper is a domain scanning script designed to identify vulnerabilities in a domain environment for security assessment purposes. It leverages various tools to gather information, but it's crucial to note that it's intended for use primarily on Kali Linux. This script will automatically download any dependencies not pre-installed on Kali.

**Dependencies:**

* Nmap (included in Kali)
* Masscan (included in Kali)
* Impacket (automatic clone from https://github.com/fortra/impacket.git)
* Rockyou.txt (automatic clone and decompression from https://github.com/zacheller/rockyou.git)
* CrackMapExec (CME) (included in Kali)
* Medusa (included in Kali)
* Hydra (included in Kali)
* Hashcat (included in Kali)

**Usage and Functionality:**

**Working Method Selection:**

1. **BASIC:** Identifies open ports, services, domain controllers (DCs), DHCP servers, and performs a basic vulnerability scan.
2. **INTERMEDIATE:** Enhances BASIC mode with enumeration of FTP, SSH, SMB, WinRM, LDAP, and RDP services, along with shared folders.
3. **ADVANCED:** Extends INTERMEDIATE mode by extracting all users, groups, shares, displaying password policy, finding disabled and never-expiring accounts, and identifying domain admins by name.

**Important Note:** Higher working methods encompass all features of lower ones. (e.g., ADVANCED includes both INTERMEDIATE and BASIC functionalities.)

**Target Network:**

* Netrange Format: 192.168.22.0/24
* Exclusion format: 192.168.22.2,192.168.22.254,192.168.22.46

  - The default gateway and host IP are automatically excluded.

**Domain Name:**

* Manual Entry: Type the domain name directly.
* Automatic Enumeration: Press Enter to attempt domain enumeration.

**Host Domain Affiliation:**

For networks with multiple domains, each address will be associated with its corresponding domain.

**Active Directory (AD) Credentials:**

For enhanced enumeration within an AD environment, valid credentials are required. Results may vary depending on security configurations. After running the script with initial credentials, you might discover higher-privileged users who can be used to re-run the script and gather more information.

**Domain Controller Identification:**

The script identifies DCs by analyzing key features on each address. The address with the highest number of matching features is deemed the DC. In case of multiple domains, each DC will be identified with its name and IP.

**EternalBlue Vulnerability Check:**

The script scans for EternalBlue vulnerability but will not exploit it in any way. A warning will be displayed if detected.

**Enumeration Techniques:**

* **DC Identification**
* **DHCP Identification**
* **Port Scanning:** TCP partial, full, and full + UDP
* **Service Banner Grabbing**
* **Nmap Scripting Engine (NSEs):**
    * `krb5-enum-users`
    * `smb-vuln-ms17-010.nse`
    * `http-enum`
    * `smb-enum-shares.nse`
* **CrackMapExec (CME):**
    * `--users`
    * `--groups` (with and without 'Domain Admins' arguement)
    * `--shares`
    * `--pass-pol`
  * **(CME Note):** PasswordNeverExpires enumeration may be attempted via WinRM RCE, but this functionality is disabled by default due to security concerns. Consider enabling it only in controlled environments.

**Exploitation (if applicable):**

* **NSEs:** `vulners.nse`, `telnet-brute`
* **Medusa:** SSH, FTP, RDP
* **Hydra:** LDAP
* **CME:** WinRM (if enabled), SMB (with caution)

**Kerberos Ticket Extraction:**

Impacket's `GetNPUsers.py` script is used for automatic ticket extraction. The script will attempt to locate the script on your system. If not found, it will be downloaded automatically. Extracted tickets will be cracked using either a custom wordlist or Rockyou.txt.

**Summary Report:**

A concise overview with key statistical findings will be provided, as scans can be time-consuming.

**Full Reports:**

* **Domain-Related Actions:** Detailed
