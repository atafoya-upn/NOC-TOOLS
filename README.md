# noc-tools

Main directory for the noc-tools project.

    # Get_CKIDs.py
    Used for collecting information from specified devices that are expected to be impacted by maintenance work. Gathers all the CKSIDs in the form of XXXXXXXX/XXXXXX/XXXXXXXX or XXXXXXXX-XXXXXX-XXXXXXXX listed in the configurations on any of our current Cisco routers. The market will still need to provide an impact list for any core equipment, as they are likely to affect services not explicitly listed in configuration files.

    # .env
    Create a .env file to store all sensitive information used as variables in the scripts. This file is not secure and is only utilized to remove sensitive information from the scripts. Just remember that the only security this provides when storing on your local machine is through obfuscation. The.env file should be stored in the same directory as the scripts.
    
    These are the current keys expected to be used for variables in this project:
    
    FTP_SERVER="<IP>"
    FTP_SERVER_BENCH="<IP>"
    FTP_USER="<USERNAME>"
    FTP_PASSWORD="<PASSWORD>"
    TACACS_USER="<USERNAME>"
    TACACS_PASSWORD="<PASSWORD>" # Will be using getpass in these scripts but that can easily be edited to allow pulling from the .env file.
    BENCH_USER="<USERNAME>"
    BENCH_PASSWORD="<PASSWORD>"

    FTP_SERVER is the IP address to reach the ftp server when doing upgrades on production routers or for anything on the provisioning bench in Albq.
    FTP_SERVER_BENCH is the IP address to reach the ftp server when doing upgrades on the provisioning bench in all other markets.
    FTP_USER is the username for downloading from the ftp server.
    FTP_PASSWORD is the password for downloading from the ftp server.
    TACACS_USER is the username for logging into devices in production.
    TACACS_PASSWORD is the password for logging into devices in production.
    BENCH_USER is the username for logging into devices on the provisioning benches.
    BENCH_PASSWORD is the password for logging into devices on the provisioning benches.


# noc-tools/UPGRADES

The UPGRADES directory contains scripts that are used to prepare and execute IOS and ROMMON upgrades on production Cisco routers.

    # 920_DOWNLOAD_CONCURRENT.py
    Used to download the IOS and ROMMON images for Cisco ASR-920 routers using concurrency to maximize speed when preparing for large scale upgrades.

    # 920_UPGRADE_CONCURRENT.py
    Used to upgrade IOS and ROMMON images for Cisco ASR-920 routers using concurrency to maximize speed when preparing for large scale upgrades. 
    *****Must only be run in a scheduled maintenance window*****

    # 540_DOWNLOAD_CONCURRENT.py
    This script is currently being written to test the best methods and functions to download the IOS images for Cisco NCS540 routers. It is not currently functional but will eventually be recompiled into the UPGRADE_ALL_CONCURRENT.py script to simplify the process of downloading and upgrading all routers.

    # UPGRADE_ALL_CONCURRENT.py
    Currently in development, this script will be used to download and upgrade IOS and ROMMON images for all Cisco routers we use.