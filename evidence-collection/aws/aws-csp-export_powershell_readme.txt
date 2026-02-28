================================================================================
  aws-csp-export.ps1  —  README
  AWS Cloud Service Provider Controls Export (PowerShell)
  Audience: AWS Administrator / Sysadmin
  PCI DSS 4.0.1 — Identity, Access, and Logging Controls
================================================================================

PURPOSE
-------
This script connects to AWS and exports account-level configuration evidence
for PCI DSS identity, access, and logging control reviews. It is read-only
and makes no changes to your AWS environment.

What is exported and why it matters for PCI DSS:

  IAM Password Policy       Req 8.3: Verify password complexity, length, history,
                            and expiry requirements are enforced for all users.

  IAM Credential Report     Req 8.2, 8.3, 8.6: The single most important IAM
  (CSV)                     file. Shows every IAM user with: whether MFA is
                            enrolled, password last used, access key ages, and
                            access key last-used dates. Assessors use this to
                            identify inactive accounts, missing MFA, and stale
                            access keys.

  IAM Users                 Req 7.2, 8.2: User accounts with their group
                            memberships and attached policies — establishes
                            who has access and what they can do.

  IAM Groups                Req 7.2: Group definitions and attached policies —
                            how access is assigned in bulk.

  IAM Roles                 Req 7.2: Role definitions with trust policies
                            (who can assume the role) and attached permissions.
                            Important for service-to-service access review.

  MFA Devices               Req 8.4, 8.5: Virtual and hardware MFA tokens
                            registered in the account.

  CloudTrail                Req 10.2, 10.3: Confirms audit logging is enabled
                            for all API calls. Shows trail configuration, whether
                            logging is active, last delivery time, and log
                            file validation status.

  S3 Buckets                Req 10.5, 10.7: Shows log storage configuration
                            per bucket — critical for confirming CloudTrail and
                            VPC flow logs are protected. Also identifies any
                            bucket with public access enabled (a finding).

  AWS Config                Req 1.1, 6.3, 12.3: Config rules validate that AWS
                            resources meet defined security standards continuously.
                            Non-compliant rules indicate controls that are failing.

  GuardDuty                 Req 10.7, 12.10: Active threat detection findings —
  (if enabled)              relevant for incident detection and response evidence.

  Security Hub              Req 12.4: Aggregated compliance posture against
  (if enabled)              enabled standards including PCI DSS. Active FAILED
                            findings map directly to failing PCI controls.


IMPORTANT — TWO SCRIPTS FOR AWS
--------------------------------
This script (aws-csp-export.ps1) covers identity, access, and logging controls.

A separate script (aws-network-export.ps1) covers network security controls:
  Security Groups, NACLs, VPCs, Route Tables, AWS Network Firewall.

Run BOTH scripts to provide complete PCI DSS network and CSP evidence.


REQUIREMENTS
------------
  - Windows PowerShell 5.1 OR PowerShell 7+ (recommended)

  - AWS Tools for PowerShell — offered for auto-install if not found:
      AWS.Tools.IdentityManagement    (IAM)
      AWS.Tools.CloudTrail            (CloudTrail)
      AWS.Tools.S3                    (S3 buckets)
      AWS.Tools.ConfigService         (AWS Config)
      AWS.Tools.GuardDuty             (GuardDuty — optional)
      AWS.Tools.SecurityHub           (Security Hub — optional)
      AWS.Tools.SecurityToken         (account ID lookup)

  - AWS credentials with read-only access. See "IAM PERMISSIONS REQUIRED".

  - Internet or Direct Connect access to AWS API endpoints.


BEFORE YOU RUN — EDIT THESE SETTINGS IN THE SCRIPT
---------------------------------------------------
Open aws-csp-export.ps1 in Notepad or VS Code and update:

    $AccessKeyId     = "YOUR_ACCESS_KEY_ID"
    $SecretAccessKey = "YOUR_SECRET_ACCESS_KEY"
    $Region          = "us-east-1"     <-- Region for Config, GuardDuty, Security Hub.
                                           IAM, S3, and CloudTrail listings are global.
    $OutputBase      = "C:\aws-export"
    $ProfileName     = ""              <-- Named profile (leave "" for access keys)

REGION NOTE:
  IAM, S3 bucket listing, and CloudTrail trail listing are account-global
  and not affected by $Region.

  AWS Config, GuardDuty, and Security Hub are regional services. Set $Region
  to each region where these services are enabled and run the script once per
  region to ensure full coverage.

  To find which regions have these services enabled:
    AWS Console > GuardDuty > (switch regions)
    AWS Console > Security Hub > (switch regions)
    AWS Console > Config > Settings > (switch regions)


IAM PERMISSIONS REQUIRED
------------------------
Attach the following AWS-managed policies to the IAM user or role:

  ReadOnlyAccess                     (covers IAM, S3, Config, CloudTrail, STS)
  AWSSecurityHubReadOnlyAccess       (Security Hub)
  AmazonGuardDutyReadOnlyAccess      (GuardDuty)

Or use this minimum inline policy:
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:GetAccountPasswordPolicy",
          "iam:ListUsers",
          "iam:ListGroups",
          "iam:ListRoles",
          "iam:ListAttachedUserPolicies",
          "iam:ListUserPolicies",
          "iam:ListGroupsForUser",
          "iam:ListAttachedGroupPolicies",
          "iam:ListGroupPolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:ListMFADevices",
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketLogging",
          "s3:GetBucketVersioning",
          "config:DescribeConfigurationRecorders",
          "config:DescribeConfigurationRecorderStatus",
          "config:DescribeConfigRules",
          "config:GetComplianceDetailsByConfigRule",
          "guardduty:ListDetectors",
          "guardduty:GetDetector",
          "guardduty:ListFindings",
          "guardduty:GetFindings",
          "securityhub:GetEnabledStandards",
          "securityhub:GetFindings",
          "securityhub:DescribeHub",
          "sts:GetCallerIdentity"
        ],
        "Resource": "*"
      }
    ]
  }


CREATING AN IAM USER FOR THIS ASSESSMENT
-----------------------------------------
  1. AWS Console > IAM > Users > Create user
     Username: pci-csp-readonly (or similar)
     Access type: Programmatic access (no console access needed)

  2. Attach policies:
     ReadOnlyAccess
     AWSSecurityHubReadOnlyAccess
     AmazonGuardDutyReadOnlyAccess

  3. After creating: copy the Access Key ID and Secret Access Key
     (shown once — store securely)

  4. After assessment: IAM > Users > your user >
     Security credentials > Deactivate or delete the access key


USING NAMED PROFILES (ALTERNATIVE TO ACCESS KEYS)
--------------------------------------------------
  If AWS SSO or CLI profiles are configured:
    Set $ProfileName = "your-profile-name" in the script
    Leave $AccessKeyId and $SecretAccessKey as ""

  To list available profiles: aws configure list-profiles


RUNNING THE SCRIPT
------------------
  1. Open PowerShell

  2. If needed (common on corporate machines):
       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  3. Navigate to the script folder:
       cd "C:\path\to\script"

  4. Run:
       .\aws-csp-export.ps1

  5. If modules are not installed, answer "yes" at the prompt.
     This requires internet access and takes 2-5 minutes (one-time).

  6. A successful run looks like:

       ========================================
         AWS CSP Controls Export (PCI DSS)
         Region  : us-east-1
         Output  : C:\aws-export\aws-csp-us-east-1-20260225_143012
       ========================================

       [ Credentials ]
         Setting AWS credentials...                 OK
         Account ID:                                123456789012

       [ IAM — Identity and Access Management ]
         Password policy...                         OK (1 items, 0.8 KB)
         Credential report (MFA + key ages)...      OK (47 users)
         IAM users (with groups + policy)...        OK (47 items, 84.3 KB)
         IAM groups (with policy attachments)...    OK (12 items, 22.1 KB)
         IAM roles (with trust + policy)...         OK (89 items, 312.4 KB)
         MFA devices (all users)...                 OK (43 items, 18.7 KB)

       [ CloudTrail ]
         Trails and logging status...               OK (3 items, 14.2 KB)

       [ S3 — Storage ]
         Buckets (policy + public access + logging) OK (28 items, 96.8 KB)

       [ AWS Config ]
         Configuration recorders...                 OK (1 items, 3.4 KB)
         Config rules and compliance...             OK (124 items, 284.7 KB)

       [ GuardDuty ]
         GuardDuty detectors...                     OK (1 items, 2.1 KB)
         GuardDuty findings (active)...             OK (7 items, 48.3 KB)

       [ Security Hub ]
         Security Hub overview + standards...       OK (1 items, 12.4 KB)
         Security Hub findings (active / failed)    OK (213 items, 1124.8 KB)


OUTPUT FILES EXPLAINED
----------------------
All files saved in: aws-csp-<REGION>-<DATE>_<TIME>
Example: C:\aws-export\aws-csp-us-east-1-20260225_143012

File                              What it contains and how to use it
------------------------------    -------------------------------------------------------
iam-credential-report.csv         THE MOST IMPORTANT IAM FILE. Open in Excel.
                                  One row per IAM user. Key columns:
                                    user               Username
                                    password_enabled   Is a console password set?
                                    password_last_used Last console login date
                                    mfa_active         TRUE/FALSE — is MFA enrolled?
                                    access_key_1_active / access_key_2_active
                                    access_key_1_last_rotated / _2_last_rotated
                                    access_key_1_last_used_date / _2_last_used_date
                                  Filter mfa_active = FALSE to find users without MFA.
                                  Filter access_key_1_last_rotated for keys older than
                                  90 days (PCI requires periodic rotation).

iam-password-policy.json          Password policy settings:
                                    MinimumPasswordLength     (PCI: >= 12)
                                    RequireUppercaseCharacters (PCI: required)
                                    RequireLowercaseCharacters (PCI: required)
                                    RequireNumbers             (PCI: required)
                                    RequireSymbols             (PCI: required)
                                    MaxPasswordAge             (PCI: <= 90 days)
                                    PasswordReusePrevention    (PCI: >= 4)
                                    AllowUsersToChangePassword

iam-users.json                    All IAM users with their Groups, attached managed
                                  policies, and inline policy names. Use to identify
                                  users with direct policy attachments (less ideal
                                  than group-based access).

iam-groups.json                   Groups with their attached policies. Cross-reference
                                  with users to understand effective access.

iam-roles.json                    Roles with TrustPolicy (who can assume the role)
                                  and attached policies. Look for overly broad trust
                                  policies (e.g., Principal: "*") or admin permissions.

iam-mfa-devices.json              All registered MFA tokens with username and device
                                  type (virtual/hardware). Cross-reference with
                                  credential report to find gaps.

cloudtrail-trails.json            All trails with IsLogging (true/false), HomeRegion,
                                  IsMultiRegionTrail, LogFileValidationEnabled,
                                  S3BucketName (where logs go), and last delivery time.
                                  PCI requires: logging enabled, multi-region or per-
                                  region coverage, log file validation on, logs secured.

s3-buckets.json                   Every S3 bucket with:
                                    PublicAccessBlock.BlockPublicAcls      (should: true)
                                    PublicAccessBlock.BlockPublicPolicy    (should: true)
                                    PublicAccessBlock.IgnorePublicAcls     (should: true)
                                    PublicAccessBlock.RestrictPublicBuckets (should: true)
                                    IsPublicViaPolicy  true = bucket is publicly accessible
                                    Policy             raw bucket policy JSON
                                    Logging.TargetBucket  where access logs go
                                    Versioning         Enabled/Suspended/Off
                                  Search "IsPublicViaPolicy" = true to find public buckets.
                                  Verify CloudTrail log buckets have logging enabled.

config-recorders.json             Config recorder status:
                                    Recording = true/false (is Config capturing changes?)
                                    LastStatus = Success/Failure
                                    LastStartTime / LastStopTime
                                  If Recording = false, Config is not active in this region.

config-rules-compliance.json      All Config rules with their compliance results.
                                  ComplianceDetails contains NON_COMPLIANT resources.
                                  PCI-relevant managed rules to look for:
                                    mfa-enabled-for-iam-console-access
                                    access-keys-rotated
                                    iam-password-policy
                                    cloudtrail-enabled
                                    cloud-trail-log-file-validation-enabled
                                    s3-bucket-public-read-prohibited
                                    s3-bucket-server-side-encryption-enabled

guardduty-detectors.json          Detector settings: status (ENABLED/DISABLED),
(if enabled)                      data sources enabled (CloudTrail, DNS, FlowLogs,
                                  S3 logs, Malware Protection).

guardduty-findings.json           Active non-archived findings. Key fields:
(if enabled)                        Severity (1-10: Critical=9+, High=7-9, Medium=4-7)
                                    Title, Description
                                    Service.Action (what triggered the finding)
                                    Resource (which AWS resource is affected)
                                    CreatedAt / UpdatedAt
                                  High and Critical findings may indicate active
                                  threats in scope for PCI.

securityhub-overview.json         Hub configuration and list of enabled compliance
(if enabled)                      standards (PCI DSS, CIS, NIST, AWS Foundational).
                                  Confirm PCI DSS standard is enabled.

securityhub-findings.json         Active FAILED findings from all enabled standards.
(if enabled)                      Key fields per finding:
                                    Title, Description, Severity.Label
                                    Compliance.Status (FAILED)
                                    Compliance.RelatedRequirements (maps to PCI reqs)
                                    Remediation.Recommendation.Text
                                  Filter RelatedRequirements for "PCI DSS" to focus
                                  on PCI-specific failing controls.

*-not-enabled.json                Written when GuardDuty or Security Hub is not enabled
                                  in the specified region. Documents that the check ran.

MANIFEST.txt                      Account ID, region, timestamp, host, user, and file
                                  list with sizes. For chain-of-custody records.


HOW TO REVIEW THE FILES ON WINDOWS
-----------------------------------
  iam-credential-report.csv — Open in Excel:
    - Data > From Text/CSV > select file > Load
    - Add filters (Data > Filter) to each column
    - Filter mfa_active = FALSE to find users missing MFA
    - Filter access_key_1_last_rotated < [date 90 days ago] for old keys

  JSON files — VS Code:
    - File > Open Folder > select the export folder
    - Click any .json file, press Shift+Alt+F to format/indent
    - Ctrl+Shift+F to search across all files
    - Search "NON_COMPLIANT" across all files to find failing controls
    - Search "IsPublicViaPolicy" to find public S3 buckets
    - Search "false" in cloudtrail-trails.json to find disabled logging

  Large files (securityhub-findings.json can be 1000+ rows):
    - Use VS Code with "Large File Support" extension
    - Or copy into Excel via Power Query (Data > Get Data > From File > JSON)


TROUBLESHOOTING
---------------
  "Setting AWS credentials... FAILED" with "InvalidClientTokenId"
      Access Key ID is invalid. Verify in IAM > Users > Security credentials.

  "Setting AWS credentials... FAILED" with "SignatureDoesNotMatch"
      Secret Access Key is wrong — check for copy/paste errors.
      Secret cannot be retrieved; create a new access key in IAM.

  "IAM users... FAILED" with "AccessDenied"
      The user lacks IAM read permissions. Attach ReadOnlyAccess policy.

  "Credential report... FAILED" with "ReportInProgress"
      The report was still generating when the script tried to retrieve it.
      Increase the retry attempts in the script (change "8" to "12" in the
      for loop, or increase the Start-Sleep duration from 5 to 8 seconds).

  "Config rules... OK (0 items)"
      AWS Config has no rules configured in $Region, or Config is not enabled.
      Check config-recorders.json — if Recording = false, Config is off.

  "GuardDuty is not enabled in region X"
      GuardDuty is not enabled in that region. This is a finding if the region
      hosts in-scope PCI systems. Document as a gap.

  "Security Hub is not enabled in region X"
      Security Hub is not configured. This is a gap for PCI DSS Req 12.4.
      Document in the assessment. The securityhub-not-enabled.json file
      serves as evidence that this was checked.

  securityhub-findings.json has thousands of entries
      Normal for accounts with many resources. Filter by:
      - Severity: search "CRITICAL" or "HIGH" first
      - Compliance.RelatedRequirements: search "PCI DSS" to focus scope
      - Use Excel Power Query to import and add filters

  S3 bucket export is slow
      Each bucket requires 5-6 individual API calls. Accounts with many
      buckets (50+) may take several minutes. This is expected.


SECURITY NOTES
--------------
  - Access keys are stored in plain text in this script. Apply NTFS
    permissions to restrict file access to only your account.

  - Create a dedicated IAM user for this assessment; do not use a shared
    admin account. Delete the user after the assessment.

  - After the assessment:
    - Deactivate or delete the access key in IAM
    - Delete or securely archive the export folder — it contains your full
      user list, policy structure, access key metadata, and security findings

================================================================================
