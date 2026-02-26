# PCI DSS Toolkit

A collection of useful scripts for both assessors and sysadmins to pull
configuration evidence from network devices, operating systems, and cloud
environments. Output is formatted for review by a PCI DSS internal or external assessor.

All scripts are **read-only**. They connect to devices or APIs, export
configuration data, and save it locally. No changes are made to any system.

---

## How This Toolkit Works

Each script is designed to be run by a sysadmin on behalf of an assessor.
The general workflow is:

1. A sysadmin receives the appropriate script for their environment
2. They update the configuration block at the top of the script (IP address,
   API credentials, output folder)
3. They run the script from a workstation that has network access to the target
4. The script saves all output to a timestamped folder
5. That folder is handed to the PCI assessor for review

Each script category includes a README with step-by-step instructions written
for a sysadmin audience, including how to generate credentials and what to
expect in the output.

---

## Evidence Categories

### Firewalls

#### FortiGate

Exports the complete FortiGate running configuration for assessor review.
Captures everything needed for a PCI DSS network security control review:

- Full running configuration (all sections, complete)
- Firewall rulebase (IPv4 and IPv6 policies)
- Network interfaces and zone assignments
- Static, BGP, and OSPF routing tables
- Address objects and address groups
- Service objects and service groups
- Administrator accounts and access profiles
- Logging and syslog destination settings
- NTP configuration

Output includes both a complete plain-text configuration file and individual
structured JSON files per table — making it easy to search the full config or
jump directly to a specific section (e.g., open firewall-policies.json to
review only the rulebase).

Scripts available for: **Bash** | **PowerShell**

---

#### Palo Alto Networks

Exports the complete Palo Alto PAN-OS running configuration and security
policy rulebase for assessor review. Covers:

- Full running configuration exported as XML (all device settings)
- Security policy rulebase with full rule details
- Address objects and address groups (resolved to actual IPs/subnets)
- Service objects and service groups (resolved to protocol/port)
- Each firewall rule flattened to source IP, destination IP, protocol, port,
  and action — ready for direct assessor review without needing to cross-
  reference object definitions manually

Output formats include XML (full config), JSON, CSV, and Excel — providing
flexibility depending on how the assessor prefers to work.

Scripts available for: **Python** | **PowerShell**

---

#### Cisco *(Coming Soon)*

Will export Cisco firewall and router configurations, including:

- Running configuration
- Access Control Lists (ACLs) with full rule detail
- Interface assignments and security levels
- NAT rules and routing tables
- Network object and object-group definitions

Planned support for: **IOS / IOS-XE** | **ASA** | **Firepower**

---

### Cloud Network Security

#### Microsoft Azure *(Coming Soon)*

Will export Azure network security configuration relevant to PCI DSS,
including:

- Network Security Group (NSG) rules — inbound and outbound, per rule with
  source, destination, protocol, port, and priority
- NSG-to-subnet and NSG-to-NIC associations
- Azure Firewall policies and rules (if in use)
- Virtual Network topology and subnet definitions
- Application Security Groups

---

#### Amazon Web Services *(Coming Soon)*

Will export AWS network security configuration relevant to PCI DSS,
including:

- Security Group rules — inbound and outbound, per group with protocol,
  port range, and CIDR or source group references
- Network ACL (NACL) rules — per subnet association with allow/deny rules
  in priority order
- VPC structure, subnet definitions, and route tables
- AWS Network Firewall policies and stateless/stateful rule groups (if in use)

---

### Operating Systems

#### Windows *(Coming Soon)*

Will export Windows host configuration relevant to PCI DSS system hardening
and access control reviews, including:

- Local user accounts and group memberships
- Password policy and account lockout policy
- Audit policy settings
- Windows Firewall rules (inbound and outbound)
- Installed software and patch levels
- Running services and their configurations
- Registry keys relevant to security hardening benchmarks

---

#### Linux *(Coming Soon)*

Will export Linux host configuration relevant to PCI DSS system hardening
and access control reviews, including:

- Local user accounts, sudo rights, and group memberships
- Password policy settings (PAM configuration)
- SSH daemon configuration
- iptables / nftables / firewalld rules
- Installed packages and patch status
- Running services (systemd units)
- Cron jobs and scheduled tasks
- Syslog and auditd configuration

---

### Cloud Service Providers

#### Amazon Web Services *(Coming Soon)*

Will export AWS account-level configuration relevant to PCI DSS identity,
access, and logging controls, including:

- IAM users, groups, roles, and policy attachments
- IAM password policy
- MFA enrollment status per user
- Access key age and last-used dates
- CloudTrail configuration and status (all regions)
- S3 bucket policies and public access settings
- AWS Config rules and compliance status
- GuardDuty and Security Hub findings summary

---

#### Microsoft Azure *(Coming Soon)*

Will export Azure tenant and subscription-level configuration relevant to
PCI DSS identity, access, and logging controls, including:

- Azure AD users, groups, and role assignments
- Privileged Identity Management (PIM) configuration (if in use)
- MFA enrollment status
- Conditional Access policies
- Azure Monitor and Diagnostic Settings (log destinations)
- Storage account access policies
- Microsoft Defender for Cloud recommendations and compliance status

---

## General Notes for Sysadmins

**Credentials**: Each script requires read-only API credentials or tokens.
Instructions for generating these are included in the per-script README files.
API tokens should be created specifically for this assessment and disabled or
deleted once the assessment is complete.

**Output location**: Scripts save all output to a local folder on the machine
running the script. No data is sent anywhere else. Copy the output folder to
a secure location and share it with your assessor through an approved channel.

**SSL certificates**: Network devices commonly use self-signed certificates.
All scripts are configured to bypass certificate validation by default. This
is expected behavior and does not indicate a security issue with the export.

**What to do with the output**: Hand the entire timestamped output folder to
your PCI assessor. Do not modify or delete any files from the folder. Each
folder includes a MANIFEST file that lists all exported files and timestamps
for chain-of-custody purposes.

**After the assessment**: Delete or securely archive all output folders. They
contain full device configurations which are sensitive. Revoke or disable any
credentials created for this assessment.
