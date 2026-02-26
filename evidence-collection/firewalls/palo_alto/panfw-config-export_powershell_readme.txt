================================================================================
  panfw-config-export.ps1  —  README
  Palo Alto Firewall Configuration Export (PowerShell)
  Audience: Firewall Administrator / Sysadmin
================================================================================

PURPOSE
-------
This script connects to a Palo Alto firewall using its XML API and downloads
the full running configuration as a date-stamped XML file. The output is
provided to a PCI DSS assessor for review.

The script does NOT make any changes to the firewall. It is read-only.


REQUIREMENTS
------------
  - Windows PowerShell 5.1 (built into Windows 10/11 and Server 2016+)
    OR PowerShell 7+ (recommended — download from microsoft.com/powershell)

  - Network access to the firewall's management interface (typically port 443)
  - A PAN-OS API key with at least read-only access (see "GENERATING AN API KEY"
    below)
  - The output directory must already exist on the machine running the script

  No additional modules or installs are required.


BEFORE YOU RUN — EDIT THESE 3 SETTINGS IN THE SCRIPT
-----------------------------------------------------
Open panfw-config-export.ps1 in Notepad or PowerShell ISE and update the
following lines near the top of the file:

    $PA_HOST   = "10.0.1.2"                 <-- Change to your firewall's IP or hostname
    $API_KEY   = "YOUR_API_KEY"             <-- Paste your API key here (see below)
    $ConfigDir = "C:\PCI-Evidence\paloalto" <-- Change to the folder where you want
                                                 the output file saved


GENERATING AN API KEY
---------------------
You need a PAN-OS API key to authenticate. Use an account that has at least
read-only (Viewer) access. Steps:

  Option A — Web UI:
    1. Log in to the firewall web UI
    2. Go to Device > Administrators
    3. Click on your username
    4. Click "Generate API Key" and copy the value

  Option B — PowerShell (replace values in angle brackets, then press Enter):

    $cred = Get-Credential
    Invoke-RestMethod "https://<FW_IP>/api/?type=keygen&user=$($cred.UserName)&password=$($cred.GetNetworkCredential().Password)" -SkipCertificateCheck

    The key is returned inside the <key> tag in the XML response.

  Treat the API key like a password. Do not share it or commit it to version
  control.


RUNNING THE SCRIPT
------------------
  1. Open PowerShell (not PowerShell ISE — use the regular console or Windows
     Terminal)
  2. Navigate to the folder containing the script:
       cd "C:\path\to\script"
  3. If prompted about execution policy, run this first (one-time, current
     session only):
       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  4. Run the script:
       .\panfw-config-export.ps1

  On success you will see:
       Connecting to <FW_IP> ...
       Configuration saved to: C:\PCI-Evidence\paloalto\pa-YYYYMMDD.xml


OUTPUT
------
  File format : XML
  File name   : pa-YYYYMMDD.xml  (e.g., pa-20260225.xml)
  Location    : The directory set in $ConfigDir

  The file contains the full PAN-OS running configuration. Hand this file to
  your PCI assessor.


EXECUTION POLICY — QUICK EXPLANATION
--------------------------------------
  Windows may block scripts from running by default. If you see an error like:
    "cannot be loaded because running scripts is disabled on this system"

  Run this in the same PowerShell window before executing the script:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  This only affects the current PowerShell session and does not change any
  system-wide settings.


TROUBLESHOOTING
---------------
  "Could not establish trust relationship" or SSL/TLS error
      - Expected on older Windows PowerShell 5.1 builds. The script includes
        an automatic SSL bypass. If you still see this, confirm you are running
        the script as written and have not removed the TrustAllCerts section.

  "The remote server returned an error: (403) Forbidden"
      - The API key is invalid or the associated account lacks permissions.
        Regenerate the key and confirm the account has at least Viewer access.

  "Unable to connect" or timeout
      - Confirm the firewall IP is correct and reachable:
          Test-NetConnection -ComputerName 10.0.1.2 -Port 443
      - Confirm port 443 is open to the management interface
      - Check that Windows Firewall is not blocking outbound port 443

  Output file is empty or contains an error message
      - Open the XML file in a browser or text editor to read the error detail
      - Common cause: wrong API key or API access not enabled on the firewall

  "Access to the path is denied"
      - Confirm the folder in $ConfigDir already exists
      - Confirm your Windows account has write permission to that folder

  Script runs but no output file appears
      - Check that $ConfigDir path is spelled correctly and exists
      - Try an absolute path such as C:\Temp and re-run


SECURITY NOTES
--------------
  - The API key is stored in plain text inside this script. Restrict access to
    the script file using NTFS permissions (only the running account should have
    Read access).
  - Run the script from a trusted, managed workstation.
  - Delete or securely archive the output XML after the assessment — it
    contains your full firewall configuration.

================================================================================
