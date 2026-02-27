================================================================================
  aws-network-export.ps1  —  README
  AWS Network Security Configuration Export (PowerShell)
  Audience: AWS Administrator / Sysadmin
================================================================================

PURPOSE
-------
This script connects to AWS using the AWS Tools for PowerShell and exports
network security configuration for review by a PCI DSS assessor. It is
read-only and makes no changes to your AWS environment.

What is exported:

  Security Groups         All inbound and outbound rules for every security
                          group in the region, including protocol, port range,
                          CIDR block, and cross-security-group references.

  Network ACLs (NACLs)    All NACL rules per subnet association, sorted in the
                          order AWS evaluates them (lowest rule number first),
                          including allow/deny action and direction (inbound/
                          outbound).

  VPC Infrastructure      VPC definitions (CIDR, state, default flag), all
                          subnets (VPC, AZ, CIDR), route tables with routes
                          and subnet associations, internet gateways, NAT
                          gateways, and VPC peering connections.

  AWS Network Firewall    Firewall instances, firewall policies (with stateless
  (if deployed)           and stateful rule group references and priorities),
                          and full rule group content including Suricata rules,
                          5-tuple rules, or domain lists.


REQUIREMENTS
------------
  - Windows PowerShell 5.1 (built into Windows 10/11 and Server 2016+)
    OR PowerShell 7+ (recommended — better JSON handling for large outputs)

  - AWS Tools for PowerShell — the script will offer to install automatically
    if not found. Modules needed:
      AWS.Tools.EC2               (VPCs, subnets, security groups, NACLs, routes)
      AWS.Tools.NetworkFirewall   (AWS Network Firewall rules)
      AWS.Tools.SecurityToken     (account ID lookup — optional but recommended)

  - AWS credentials with read-only access to the resources above. See
    "IAM PERMISSIONS REQUIRED" below.

  - Network access to AWS (internet or Direct Connect / VPN to AWS endpoints)


BEFORE YOU RUN — EDIT THESE SETTINGS IN THE SCRIPT
---------------------------------------------------
Open aws-network-export.ps1 in Notepad or VS Code and update the following
lines near the top of the file:

    $AccessKeyId     = "YOUR_ACCESS_KEY_ID"     <-- AWS access key (see below)
    $SecretAccessKey = "YOUR_SECRET_ACCESS_KEY" <-- AWS secret key (see below)
    $Region          = "us-east-1"              <-- AWS region to export
                                                    (run once per region)
    $OutputBase      = "C:\aws-export"          <-- Output folder (auto-created)

    $ProfileName     = ""                       <-- Optional: named profile
                                                    (see "USING AWS PROFILES")

REGION NOTE:
  AWS resources are regional. Run the script once for each region that is in
  scope for the PCI assessment. Common regions:
    us-east-1      (US East - N. Virginia)
    us-east-2      (US East - Ohio)
    us-west-1      (US West - N. California)
    us-west-2      (US West - Oregon)
    eu-west-1      (Europe - Ireland)
    ap-southeast-1 (Asia Pacific - Singapore)

  To find which regions have your resources:
    AWS Console > EC2 > top-right region selector
    AWS CLI: aws ec2 describe-regions --all-regions


IAM PERMISSIONS REQUIRED
------------------------
The script needs a read-only IAM user or role. The minimum required permissions
are listed below. The easiest approach is to attach the AWS-managed policies:

  Managed policies (attach to the IAM user/role):
    - AmazonVPCReadOnlyAccess
    - AWSNetworkFirewallReadOnlyAccess  (only needed if Network Firewall is used)

  Or as an inline policy (minimum required actions):
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "ec2:DescribeRouteTables",
            "ec2:DescribeInternetGateways",
            "ec2:DescribeNatGateways",
            "ec2:DescribeVpcPeeringConnections",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeNetworkAcls",
            "network-firewall:ListFirewalls",
            "network-firewall:DescribeFirewall",
            "network-firewall:ListFirewallPolicies",
            "network-firewall:DescribeFirewallPolicy",
            "network-firewall:ListRuleGroups",
            "network-firewall:DescribeRuleGroup",
            "sts:GetCallerIdentity"
          ],
          "Resource": "*"
        }
      ]
    }


CREATING AN IAM USER FOR THIS ASSESSMENT
-----------------------------------------
Best practice: create a dedicated IAM user for this assessment, then disable
or delete it when the assessment is complete.

  Step 1 — Create the user:
    AWS Console > IAM > Users > Create user
    Username: pci-readonly-assessor (or similar)
    Access type: Programmatic access (Access key)
    Do NOT grant console access

  Step 2 — Attach permissions:
    Attach policies: AmazonVPCReadOnlyAccess
    (and AWSNetworkFirewallReadOnlyAccess if applicable)

  Step 3 — Get the access key:
    After creating the user, download or copy:
      Access Key ID     → paste into $AccessKeyId in the script
      Secret Access Key → paste into $SecretAccessKey in the script
    This is shown only once. Store it securely.

  Step 4 — Clean up after the assessment:
    IAM > Users > pci-readonly-assessor > Security credentials > Deactivate
    or delete the access key (or delete the entire user).


USING AWS PROFILES (ALTERNATIVE TO ACCESS KEYS)
-------------------------------------------------
If your organization uses AWS SSO, AWS CLI named profiles, or Instance Roles,
you can use those instead of entering access keys in the script.

  Option A — Named profile from ~/.aws/credentials or AWS SSO:
    Set $ProfileName = "your-profile-name" in the script.
    Leave $AccessKeyId and $SecretAccessKey as "".
    To see your available profiles: aws configure list-profiles

  Option B — Environment variables (already set before running the script):
    If $AWS_ACCESS_KEY_ID and $AWS_SECRET_ACCESS_KEY are set in your
    environment, leave all CONFIG values blank. The script will use the
    default credential chain automatically.

  Option C — IAM Role on EC2 / Instance Profile:
    If running on an EC2 instance with an attached IAM role, leave all
    CONFIG values blank. The credential chain will use the instance role.


RUNNING THE SCRIPT
------------------
  1. Open PowerShell (search "PowerShell" in the Start menu)

  2. If execution policy blocks scripts (common on corporate machines):
       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  3. Navigate to the script folder:
       cd "C:\path\to\script"

  4. Run it:
       .\aws-network-export.ps1

  5. If AWS Tools are not installed, the script prompts:
       "Install from PSGallery now? (yes/no)"
     Type "yes" — this requires internet access and takes 1-3 minutes.
     It only needs to be done once.

  6. A successful run looks like:

       ========================================
         AWS Network Security Export
         Region  : us-east-1
         Output  : C:\aws-export\aws-us-east-1-20260225_143012
       ========================================

       [ Credentials ]
         Setting AWS credentials...                OK
         Account ID:                               123456789012

       [ VPC infrastructure ]
         VPCs                                      OK (3 items, 4.2 KB)
         Subnets                                   OK (18 items, 22.1 KB)
         Route tables                              OK (6 items, 8.7 KB)
         Internet gateways                         OK (2 items, 1.4 KB)
         NAT gateways                              OK (3 items, 5.2 KB)
         VPC peering connections                   OK (1 items, 2.1 KB)

       [ Network access controls ]
         Security groups                           OK (24 items, 48.3 KB)
         Network ACLs (NACLs)                      OK (5 items, 12.7 KB)

       [ AWS Network Firewall ]
         No AWS Network Firewall resources found in region us-east-1


OUTPUT FILES EXPLAINED
----------------------
All files are saved in a folder named:
  aws-<REGION>-<DATE>_<TIME>
  Example: C:\aws-export\aws-us-east-1-20260225_143012

File                          What it contains
---------------------------   -------------------------------------------------------
security-groups.json          All security groups with their full inbound rules
                              (IpPermissions) and outbound rules (IpPermissionsEgress).
                              Each rule includes: protocol, port range (FromPort/ToPort),
                              CIDR block (Ipv4Ranges/Ipv6Ranges), and cross-SG references
                              (UserIdGroupPairs). Critical for PCI firewall rule review.

network-acls.json             All NACLs with rules sorted by rule number (evaluation order).
                              Each rule includes: direction (Egress=true means outbound),
                              rule number, protocol, action (allow/deny), CIDR block,
                              and port range. Also includes subnet associations showing
                              which subnets each NACL protects.

vpcs.json                     VPC definitions: ID, CIDR blocks, state (available/pending),
                              whether it is the default VPC, and tags (including Name).
                              Multiple CIDRs shown if secondary CIDRs are associated.

subnets.json                  All subnets: ID, VPC ID, CIDR block, availability zone,
                              state, and whether auto-assign public IP is enabled.
                              Tags include the subnet Name for identification.

route-tables.json             All route tables with their routes (destination CIDR,
                              next hop type and ID: IGW, NAT GW, VPC peer, TGW, etc.)
                              and subnet associations. The "Main" flag indicates the
                              default route table for the VPC.

internet-gateways.json        Internet gateways and their VPC attachments.

nat-gateways.json             NAT gateways: ID, VPC, subnet, state, and elastic IP.
                              Shows whether NAT is public (internet-facing) or private.

vpc-peering.json              VPC peering connections showing requester and accepter
                              VPC/account/region/CIDR. Important for understanding
                              cross-VPC and cross-account connectivity.

nfw-firewalls.json            AWS Network Firewall instances with their VPC ID,
(if deployed)                 subnet mappings, and associated firewall policy ARN.

nfw-policies.json             Firewall policies with their stateless and stateful
(if deployed)                 rule group references, priorities, and default actions
                              (what happens to traffic that matches no rule).

nfw-rule-groups.json          Full rule group content for all groups:
(if deployed)                   Stateless groups: 5-tuple rules (src/dst CIDR,
                                  src/dst port range, protocol, action)
                                Stateful groups: Suricata-format IDS/IPS rules
                                  or domain list (allow/deny domains by category)

nfw-not-deployed.json         Written when no Network Firewall is found. Confirms
                              the check was run — absence of firewall is documented.

MANIFEST.txt                  Account ID, region, export timestamp, machine name,
                              and file list with sizes. For chain-of-custody records.


HOW TO REVIEW THE FILES ON WINDOWS
-----------------------------------
  VS Code (recommended):
    - Download: code.visualstudio.com
    - Open the export folder: File > Open Folder
    - Click any .json file — it opens as raw JSON
    - Press Shift+Alt+F (Format Document) to pretty-print with indentation
    - Use Ctrl+F to search within a file
    - Use Ctrl+Shift+F to search across all files (e.g., search "0.0.0.0/0"
      to find any rule that allows traffic from the entire internet)

  Useful search terms for security review:
    "0.0.0.0/0"         Any rule allowing ALL IPv4 sources (broad access)
    "::/0"              Any rule allowing ALL IPv6 sources
    "-1"                Protocol = all (all traffic rule)
    "IpPermissions"     Inbound rules section in security groups
    "IpPermissionsEgress" Outbound rules section in security groups
    "RuleAction"        In NACLs: "allow" or "deny"
    "Egress"            In NACLs: true = outbound rule, false = inbound rule
    "IsDefault"         Default VPC or default NACL flag
    "GatewayId"         In route tables: "igw-" = internet gateway route

  Notepad++ (lightweight):
    - Download: notepad-plus-plus.org
    - Language > JSON for syntax coloring
    - Plugins > JSON Viewer (install via Plugin Admin) for tree view


TROUBLESHOOTING
---------------
  "cannot be loaded because running scripts is disabled on this system"
      Run first (current session only):
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  "Setting AWS credentials... FAILED" with "InvalidClientTokenId"
      - The Access Key ID is invalid or has been deactivated
      - Verify in IAM Console: Users > your user > Security credentials
      - Regenerate the access key if needed

  "Setting AWS credentials... FAILED" with "SignatureDoesNotMatch"
      - The Secret Access Key is incorrect — double-check for copy/paste errors
      - Secret keys cannot be retrieved after creation; you may need to create
        a new access key in IAM

  "Setting AWS credentials... FAILED" with "The security token is invalid"
      - If using temporary credentials (STS/SSO), the token may have expired
      - Re-authenticate via AWS SSO or re-run aws configure sso

  "Security groups... FAILED" with "UnauthorizedOperation" or "AccessDenied"
      - The IAM user/role lacks the required permission (e.g., ec2:DescribeSecurityGroups)
      - Add the missing permission to the IAM policy — see IAM PERMISSIONS REQUIRED

  "No AWS Network Firewall resources found in region X"
      - This is expected if Network Firewall is not deployed. Not an error.
      - If you believe Network Firewall IS deployed, confirm you are checking
        the correct region (firewalls are regional resources)

  JSON files are very large and VS Code is slow to open them
      - Install the "Large File Support" extension in VS Code
      - Or use Notepad++ which handles large files better
      - In VS Code, disable word wrap for large files: View > Word Wrap

  Some items show only 0 KB or empty arrays
      - The resource type may not exist in this region (e.g., no VPC peering)
      - This is a valid finding — document "none found" in the assessment


SECURITY NOTES
--------------
  - Access keys are stored in plain text in this script. Restrict file access
    using NTFS permissions so only your account can read the script file.

  - Use a dedicated IAM user created for this assessment, not a shared admin
    account. Attach only the read-only permissions listed above.

  - After the assessment is complete:
    - Deactivate or delete the access key in IAM
    - Delete or disable the IAM user if it was created for this assessment
    - Delete or securely archive the export folder — it documents your entire
      network security posture and subnet topology

  - If your organization has a policy against programmatic access keys,
    use a named AWS profile or IAM role instead (see USING AWS PROFILES).

================================================================================
