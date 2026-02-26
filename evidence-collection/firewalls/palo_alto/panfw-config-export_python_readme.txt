================================================================================
  panfw-config-export.py  —  README
  Palo Alto Firewall Configuration Export (Python)
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
  - Python 3.7 or later
  - The "requests" library installed:
      pip install requests

  - Network access to the firewall's management interface (typically port 443)
  - A PAN-OS API key with at least read-only access (see "GENERATING AN API KEY"
    below)
  - The output directory must already exist on the machine running the script


BEFORE YOU RUN — EDIT THESE 3 SETTINGS IN THE SCRIPT
-----------------------------------------------------
Open panfw-config-export.py in any text editor and update the following lines
near the top of the file:

    PA_HOST    = "10.0.1.2"            <-- Change to your firewall's IP or hostname
    API_KEY    = "YOUR_API_KEY"        <-- Paste your API key here (see below)
    CONFIG_DIR = "/config/paloalto"    <-- Change to the folder where you want
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

  Option B — Command line (replace values in angle brackets):
    curl -k "https://<FW_IP>/api/?type=keygen&user=<USERNAME>&password=<PASSWORD>"

    The key is returned inside the <key> tag in the XML response.

  Treat the API key like a password. Do not share it or commit it to source
  control.


RUNNING THE SCRIPT
------------------
  1. Open a terminal (Linux/macOS) or Command Prompt / PowerShell (Windows)
  2. Navigate to the folder containing the script
  3. Run:
       python3 panfw-config-export.py

  On success you will see no output. A file named pa-YYYYMMDD.xml will be
  created in your CONFIG_DIR (e.g., pa-20260225.xml).


OUTPUT
------
  File format : XML
  File name   : pa-YYYYMMDD.xml  (e.g., pa-20260225.xml)
  Location    : The directory set in CONFIG_DIR

  The file contains the full PAN-OS running configuration. Hand this file to
  your PCI assessor.


TROUBLESHOOTING
---------------
  "ModuleNotFoundError: No module named 'requests'"
      Run: pip install requests

  "ConnectionError" or timeout
      - Confirm the firewall IP is correct and reachable from this machine
      - Confirm port 443 is open to the management interface
      - Check that no host-based firewall is blocking the connection

  "Invalid credential" or empty/error XML in the output file
      - Verify the API key is correct and has not expired
      - Confirm the account has not been locked out

  SSL certificate warning (script still runs)
      - Expected. Palo Alto firewalls commonly use self-signed certificates.
        The script skips certificate verification intentionally.

  Permission denied writing the file
      - Make sure CONFIG_DIR exists and you have write access to it


SECURITY NOTES
--------------
  - The API key is stored in plain text in this script. Restrict access to the
    script file (e.g., chmod 600 on Linux).
  - Run the script from a trusted, managed workstation.
  - Delete or securely archive the output XML after the assessment — it
    contains your full firewall configuration.

================================================================================
