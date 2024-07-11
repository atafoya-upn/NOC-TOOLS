#!/usr/bin/python3

#####################################################################################
#   920_UPGRADE_CONCURRENT.py Ver 2.0.0                                             #
#   Author: Adam Tafoya                                                             #
# Dependencies:                                                                     #
#   Netmiko                                                                         #
# Script Description:                                                               #
#   This Python script is designed for bulk upgrading Cisco IOS-XE devices,         #
#   specifically ASR-920s, in a production network environment. It operates by      #
#   sequentially upgrading devices on each ring of the network, one device at a     #
#   time. The script verifies the presence of required dependencies, such as        #
#   Netmiko, and prompts the user for installation if missing. It also facilitates  #
#   user authentication, retrieves a list of devices to upgrade, and initiates the  #
#   upgrade process. The upgrade process includes pre-checks, upgrade execution,    #
#   and post-checks to ensure successful upgrades. Additionally, the script handles #
#   error logging and provides a graceful shutdown mechanism.                       #
#####################################################################################

import importlib.util
import sys
import time
from datetime import datetime
import re
import logging
import signal
from concurrent.futures import ThreadPoolExecutor
import getpass
from netmiko import ConnectHandler
import threading
import traceback
import os


class ConnectionError(Exception):
    pass

class UnreachableError(Exception):
    pass

# Thread-local storage to keep track of device information
thread_local = threading.local()

# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define the log directory and log file path
log_dir = os.path.join(script_dir, 'logs')
log_file_path = os.path.join(log_dir, 'netmiko_ug.log')
devices_down_log = os.path.join(log_dir, 'nodes_down.log')
could_not_upgrade_log = os.path.join(log_dir, 'could_not_upgrade.log')
failed_to_restore_log = os.path.join(log_dir, 'failed_to_restore.log')

def setup_logger():
    """Set up the logging format and handler."""
    try:
        # Create logger using netmiko's logger
        logger = logging.getLogger('netmiko')
        logger = logging.getLogger('NetmikoLogger')
        logger.setLevel(logging.DEBUG)

        # Remove any existing handlers
        if logger.hasHandlers():
            logger.handlers.clear()

        # Create a file handler which logs even debug messages
        fh = logging.FileHandler(log_file_path)
        fh.setLevel(logging.DEBUG)

        # Create a console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)

        # Create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(device)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        # Add the handlers to the logger
        logger.addHandler(fh)
        logger.addHandler(ch)

        return logger
    
    except Exception:
        print("An unexpected error occurred while setting up the logger.")
        traceback.print_exc()
        raise


# Initialize the logger
logger = setup_logger()


# Adding the custom attribute to logger records
def add_device_info(record):
    record.device = getattr(thread_local, 'device', 'unknown')
    return True


# Add a filter to include the device info in all log records
logger.addFilter(add_device_info)


# Function to write additional logs: nodes_down.log, could_not_upgrade.log,
# and failed_to_restore.log.
def write_to_log_file(file_path, data):
    """
    Writes data to a file. Data can be either a string or a list of strings.

    :param str file_path: Path to the file to write
    :param data: Data to write (string or list of strings)
    """
    try:
        if file_path is None:
            raise ValueError("file_path is None")

        if not isinstance(data, (str, list)):
            raise ValueError("data must be either a string or a list")

        with open(file_path, "a") as file:
            if isinstance(data, str):
                try:
                    file.write(
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        + " - "
                        + data
                        + "\n"
                    )
                except Exception:  # pylint: disable=broad-except
                    traceback.print_exc()
            elif isinstance(data, list):
                for item in data:
                    try:
                        file.write(
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            + " - "
                            + str(item)
                            + "\n"
                        )
                    except Exception:  # pylint: disable=broad-except
                        traceback.print_exc()

    except Exception:  # pylint: disable=broad-except
        traceback.print_exc()


# Function to check if a package is installed. Used for checking Netmiko.
def check_dependency(package_name):
    """Check if a package is installed."""
    spec = importlib.util.find_spec(package_name)
    return spec is not None


# Function to install a package using pip. Used to install Netmiko if
# dependency check fails.
def install_package(package_name):
    """Install a package using pip."""
    import subprocess

    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", package_name]
    )


# Check if netmiko is installed
if not check_dependency("netmiko"):
    print("netmiko is not installed. Would you like to install it now? (y/n)")
    choice = input().lower()
    if choice == "y":
        install_package("netmiko")
    else:
        print(
            "netmiko is required for this script to run. Please install it " \
                "and try again."
        )
        sys.exit(1)


# Function to handle graceful shutdown
def graceful_shutdown():
    logging.info("Shutting down gracefully...")
    sys.exit(0)


# Register signal handlers for graceful shutdown
signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)


def list_append():
    """
    Function to collect IP addresses of nodes in each ring.
    Prompts user to enter number of rings and nodes in each ring.
    Organizes IP addresses into list of lists, with inner list representing
    nodes in a ring. Returns list of lists containing IP addresses of nodes.
    """
    ring_count = input("Enter number of rings: ")
    list = []
    for i in range(int(ring_count)):
        nodes_in_ring = input(f"Enter number of nodes in ring{str(i)}: ")
        ring_list = [
            input(f"Enter node{str(j)} IP: ")
            for j in range(int(nodes_in_ring))
        ]
        list.append(ring_list)
    return list


def ping(host):
    """
    A function that checks if a host is pingable.
    It uses the ping command with the -n flag for Windows and -c for Linux.

    Args:
        host (str): The IP address of the host to ping.

    Returns:
        bool: True if the host is pingable, False otherwise.
    """
    import platform
    import subprocess

    # Determine the ping command based on the operating system
    param = "-n" if platform.system().lower() == "windows" else "-c"
    count = "1" if platform.system().lower() == "windows" else "5"

    # Build the ping command
    command = ["ping", param, count, host]

    try:
        # Execute the ping command
        output = subprocess.check_output(
            command, universal_newlines=True, stderr=subprocess.STDOUT
        )

        # Check for specific undesirable output
        if "TTL expired in transit" in output:
            return False

        # Check if there are any replies indicating success
        if "Reply from" in output or "bytes from" in output:
            # Optional: Additional checks to ensure the reply is from the expected IP
            return True

    except subprocess.CalledProcessError:
        # If the ping command fails, it will raise a CalledProcessError
        return False

    return False


def run_checks(device, ios_file, rom_file, after_reload):
    """
    A function that checks various conditions of a device based on input parameters.
    It connects to the device, retrieves platform and version information, and checks file integrity.
    If the device requires updates or files, it sets corresponding flags.

    Args:
        device (dict): A dictionary containing device connection information.
        ios_file (str): The name of the IOS file to be checked.
        rom_file (str): The name of the ROM file to be checked.

    Returns:
        dict or None: A dictionary containing device information if connection is successful, None otherwise.

    Raises:
        ConnectionRefusedError: If the connection to the device is refused.
        TimeoutError: If the connection to the device times out.
        EOFError: If the connection to the device is closed unexpectedly.
        Exception: If any other error occurs during the reload process.
    """
    need_ios = False
    need_rom = False
    ios_hash_cmd = (
        f"verify /md5 bootflash:{ios_file} 2dd77405109154cf224fcb4536264421"
    )
    rom_hash_cmd = (
        f"verify /md5 bootflash:{rom_file} 4bbba2e41d832f5f4b3d3cf58dbb9f15"
    )
    need_ios_file = False
    need_rom_file = False
    acceptable_ver = "16.12.6"
    acceptable_rom = "15.6(48r)S"
    rom_with_issues = ["15.6(43r)S", "15.6(44r)S"]
    workaround_ver = "17.3.1"
    workaround_file = "asr920-universalk9_npe.17.03.01.SPA.bin"
    device_info = {}
    try:
        with ConnectHandler(**device) as connection:
            # Send commands to collect device info using textfsm
            platform = connection.send_command(
                "show platform diag", use_textfsm=True, read_timeout=30
            )
            version = connection.send_command(
                "show version", use_textfsm=True, read_timeout=30
            )
            directory = connection.send_command(
                "dir", use_textfsm=True, read_timeout=30
            )
            # Assign values to variables based on command output
            node_name = version[0]["hostname"]
            ios_ver = version[0]["version"]
            rom_version = platform[0]["firmware_version"]
            # Assign flags to be used later for deciding if the device requires an update and if files need to be downloaded
            if rom_version in rom_with_issues:
                if ios_ver != workaround_ver:
                    need_rom = False
                    acceptable_ver = workaround_ver
                    ios_file = workaround_file
                    ios_hash_cmd = f"verify /md5 bootflash:{ios_file} bd8303eaf5a9a5b1db24e85a93b80cc6"
                    workaround_needed = True
                    print(
                        f"{node_name} will be first be upgraded to IOS 17.3.1, then downgraded to 16.12.6 to upgrade ROMMON."
                    )
                else:
                    need_rom = True
                    workaround_needed = False
            elif rom_version != acceptable_rom:
                need_rom = True
                workaround_needed = False
            else:
                need_rom = False
                workaround_needed = False
            if ios_ver != acceptable_ver:
                need_ios = True
            else:
                need_ios = False
            # Create a list to store file names from the 'dir' command
            file_list = []
            # Loop through the 'dir' command output and append file names to the list ignoring folders
            for dir_entry in directory:
                if "d" in dir_entry["permissions"]:
                    continue
                else:
                    file_list.append(dir_entry["name"])
            # Check for the correct ios file in the list and run integrity check
            if ios_file not in file_list:
                need_ios_file = True
            else:
                ios_hash = connection.send_command(
                    ios_hash_cmd, read_timeout=60
                )
                if "Verified" not in ios_hash:
                    need_ios_file = True
                else:
                    need_ios_file = False
            # Check for the correct rom file in the list and run integrity check
            if rom_file not in file_list:
                need_rom_file = True
            else:
                rom_hash = connection.send_command(
                    rom_hash_cmd, read_timeout=60
                )
                if "Verified" not in rom_hash:
                    need_rom_file = True
                else:
                    need_rom_file = False
            # Create a dictionary to store device information and flags
            device_info = {
                "node_name": node_name,
                "device_ip": device["ip"],
                "ios_ver": ios_ver,
                "rom_version": rom_version,
                "need_ios": need_ios,
                "need_ios_file": need_ios_file,
                "need_rom": need_rom,
                "need_rom_file": need_rom_file,
                "workaround_needed": workaround_needed,
                "workaround_file": workaround_file,
            }
            # For testing, cancel reload after finishing run through the majority of the script
            if after_reload:
                # print(f"{device["ip"]}: Post-checks complete for {node_name}.")
                pass
    # Catch exceptions and print error messages.
    # If any exception is caught, set device_info to None to indicate that the device is not reachable.
    except ConnectionRefusedError as err:
        print(f"Connection Refused: {err}")
        logger.error(f"Connection Refused: {err}")
        device_info = None
        pass
    except TimeoutError as err:
        print(f"Connection Timeout: {err}")
        logger.error(f"Connection Timeout: {err}")
        device_info = None
        pass
    except EOFError as err:
        print(f"Connection EOF: {err}")
        logger.error(f"Connection EOF: {err}")
        device_info = None
        pass
    except Exception as err:
        print(f"Connection Error: {err}")
        logger.error(f"Connection Error: {err}")
        device_info = None
        pass
    # Return device_info as a dictionary or None if an exception was caught.
    finally:
        return device_info


def ring_check(connection):
    """
    Checks if the ring is in duplex mode by verifying if the OSPF border-routers have a repair path.

    Args:
        connection (object): The connection object used to send commands to the device.

    Returns:
        bool: True if the ring is in duplex mode, False otherwise.
    """
    # Using the ospf border-routers will produce the needed output from the show ip route command regardless of whether the ring uses segment routing or not.
    ospf_BR_output = connection.send_command(
        r"sh ip os bor | b ^i", read_timeout=60
    )
    # Collects just the IP addresses from the output.
    br_ip_addresses = re.findall(
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ospf_BR_output
    )
    # Loops through the border-router IP addresses and checks if they have a repair path.
    for ip in br_ip_addresses:
        command = f"show ip route {ip}"
        route_output = connection.send_command(command, read_timeout=60)
        keywords = [
            "Repair Path",
            "Backup (TI-LFA)",
            "Backup",
            "Backup (Local-LFA)",
        ]
        if any(keyword in route_output for keyword in keywords):
            return True
        else:
            logger.info(f"{ip} does not have a repair path: \n{route_output}")
            return False


def reload(device, ios_file, rom_file, need_rom):
    """
    Reloads a device with the specified IOS and ROM files.

    Args:
        device (dict): A dictionary containing device connection information.
        ios_file (str): The name of the IOS file to be used for reloading.
        rom_file (str): The name of the ROM file to be used for reloading.
        need_rom (bool): A flag indicating whether a ROM upgrade is needed.

    Returns:
        bool: True if reload commands are sent successfully, False otherwise.

    Raises:
        ConnectionRefusedError: If the connection to the device is refused.
        TimeoutError: If the connection to the device times out.
        EOFError: If the connection to the device is closed unexpectedly.
        Exception: If any other error occurs during the reload process.
    """
    # List of configuration commands to be sent to the device
    config = [
        "license accept end user agreement\n",
        "yes\n",
        "no boot system\n",
        f"boot system flash {ios_file}\n",
    ]
    rom_cmd = f"upgrade rom-monitor filename bootflash:{rom_file} all"
    # Reload command. Currently schedules reload for 1 minute to give it time to confirm command was sent.
    reload_cmds = [
        "\n",
        "reload in 1 reason firmware upgrade",
        "\n",
        "\n",
    ]
    try:
        with ConnectHandler(**device) as connection:
            reload_status = {
                "device_reloading": False,
                "repair_path": False,
            }
            # Send configuration commands and save running configuration
            connection.send_config_set(
                config, read_timeout=60, cmd_verify=False
            )
            # Send ROM upgrade command if needed
            if need_rom is True:
                connection.send_command(rom_cmd, read_timeout=180)
            else:
                print(f"{device['ip']}: No need for ROM upgrade")
            # Check if device is on a ring or p2p. Skips if COE in SNMP
            # contact, assuming it's a core device.
            snmp_contact = connection.send_command(
                "show snmp contact", read_timeout=30
            )
            if "MOE" in snmp_contact:
                print(
                    f"{device['ip']}: Checking for a repair path on {snmp_contact}..."
                )
                reload_status["repair_path"] = ring_check(connection)
            elif "COE" in snmp_contact:
                print(
                    f"{device['ip']} is on a COE ring: {snmp_contact}.\nThis "
                    "suggests it is a core device and you must run the upgrade"
                    " manually."
                )
                reload_status["repair_path"] = False
            else:
                # If device is on a P2P rather than a ring, set to reload
                reload_status["repair_path"] = True
                print(f"{device['ip']}: Not on a ring ({snmp_contact}).")
            if reload_status["repair_path"]:
                logger.info(
                    f"{device['ip']}: Saving configuration and sending reload command..."
                )
                # Save configuration
                connection.save_config()
                # Send reload commands
                for cmd in reload_cmds:
                    connection.write_channel(cmd)
                # Determine if reload commands were sent successfully
                sh_reload = connection.send_command(
                    "show reload", read_timeout=180
                )
                if "scheduled" in sh_reload:
                    reload_status["device_reloading"] = True
                    print(f"{device['ip']}: Reloading...")
                else:
                    reload_status["device_reloading"] = False
                    print(f"{device['ip']} is not scheduled for reload.")
                    print(sh_reload)
            else:
                print(f"{device['ip']}: {snmp_contact} is in simplex!!!")
                reload_status["device_reloading"] = False
    # Catch exceptions and print error messages. Setting device_reloading to
    # False if an exception is caught.
    except ConnectionRefusedError as err:
        print(f"Connection Refused: {err}")
        logger.error(f"Connection Refused: {err}")
        reload_status["device_reloading"] = False
        pass
    except TimeoutError as err:
        print(f"Connection Timeout: {err}")
        logger.error(f"Connection Timeout: {err}")
        reload_status["device_reloading"] = False
        pass
    except EOFError as err:
        print(f"Connection EOF: {err}")
        logger.error(f"Connection EOF: {err}")
        reload_status["device_reloading"] = False
        pass
    except Exception as err:
        if ping(device["ip"]):
            time.sleep(180.0)
            if ping(device["ip"]):
                print(f"Connection Error: {err}")
                logger.error(f"Connection Error: {err}")
                reload_status["device_reloading"] = False
                pass
            else:
                reload_status["device_reloading"] = True
                logger.error(f"Connection Error: {err}")
                pass
    # Return device_reloading as a boolean value
    finally:
        return reload_status


def upgrade(list_1):
    """
    Upgrade function that processes a list of nodes to determine if they need
    upgrades, perform upgrades, and check if the upgrade was successful.

    Parameters:
        list_1 (list): A list of IP addresses representing nodes to be
            upgraded.

    Returns:
        tuple: A tuple containing three lists - nodes that failed to upgrade,
            nodes that could not be upgraded, and nodes that failed to restore
            after reload.
    """
    # Initialize list variables for nodes that are down, nodes that could not
    # be upgraded or failed to upgrade, and nodes that failed to restore after
    # reload.
    nodes_down = []
    could_not_upgrade = []
    failed_to_restore = []
    # Set rom file name variable. Can adjust later to be passed as arguments
    # to the function.
    rom_file = "asr920_15_6_48r_s_rommon.pkg"
    # Initialize boolean variables for reload logic.
    ios_ready_for_reload = False
    rom_ready_for_reload = False
    ready_for_reload = False
    # Begin looping through nodes in the ring. With multi-threading, this could
    # be done in parallel so one node in each ring is processed concurrently.
    x = len(list_1)
    for i in range(0, x):
        node_ip = list_1[i]
        logger.info("Starting checks on " + node_ip)
        # Set device connection information.
        device = {
            "device_type": "cisco_xe",
            "ip": node_ip,
            "username": username,
            "password": password,
            "blocking_timeout": 240,  # Adjust the timeout value (in seconds)
            # as needed
            "session_timeout": 300,  # Adjust the session timeout value (in
            # seconds) as needed
            "keepalive": 30,  # Adjust the keepalive interval (in seconds) as
            # needed
            "fast_cli": False, # Set as False for Cisco devices.
        }
        # Variable to differentiate between pre and post checks.
        after_reload = False
        # Flag to reload node. Used for reloading twice if workaround is
        # needed.
        reload_flag = True
        # Loop for going through reload process again if needed for workaround.
        while reload_flag is True:
            # Set ios file name variable. Can adjust later to be passed as
            # arguments to the function.
            ios_file = "asr920-universalk9_npe.16.12.06.SPA.bin"
            # Run checks on device and return dictionary of results.
            pre_check = run_checks(device, ios_file, rom_file, after_reload)
            # Add nodes that are down to the nodes_down list.
            if pre_check is None:
                nodes_down.append(node_ip)
                print(
                    f"Failed to connect to {node_ip}. Skipping the rest of the ring."
                )
                logger.info(
                    f"Failed to connect to {node_ip}. Added to nodes_down list."
                )
                # Continue to next node on the ring in case failed connection
                # wasn't due to node being down.
                break
            # Process pre-check results to determine if the node will be
            # reloaded.
            else:
                logger.info(
                    "Processing results for "
                    + node_ip
                    + ": {}".format(pre_check)
                )
                # Continue to next node on the ring if the node doesn't need to
                # be upgraded
                if (
                    pre_check["need_ios"] is False
                    and pre_check["need_rom"] is False
                ):
                    print(f"No need to update {pre_check['node_name']}")
                    logger.info(
                        f"No need to update {node_ip}. Continuing to next node on the ring."
                    )
                    break
                # Decide if the node can be upgraded without downloading any
                # files. Can add function to dowload missing files later.
                else:
                    if pre_check["need_ios"] is False:
                        ios_ready_for_reload = True
                    else:
                        if pre_check["need_ios_file"] is True:
                            ios_ready_for_reload = False
                        else:
                            ios_ready_for_reload = True
                    if pre_check["need_rom"] is False:
                        rom_ready_for_reload = True
                    else:
                        if pre_check["need_rom_file"] is True:
                            rom_ready_for_reload = False
                        else:
                            rom_ready_for_reload = True
                    if (
                        ios_ready_for_reload is True
                        and rom_ready_for_reload is True
                    ):
                        ready_for_reload = True
                    else:
                        ready_for_reload = False
                        could_not_upgrade.append(pre_check)
                        logger.info(
                            node_ip
                            + " failed pre-checks. Added to could_not_upgrade list."
                        )
                        break
            # Run reload commands and wait for reload to complete.
            if ready_for_reload:
                # If the node needs a workaround, set the ios_file variable to the workaround file. Otherwise, it will only be reloaded once (or once more if it needed a workaround).
                if pre_check["workaround_needed"] is True:
                    ios_file = pre_check["workaround_file"]
                    last_reload = False
                else:
                    last_reload = True
                logger.info("Reloading " + node_ip)
                reload_result = reload(
                    device, ios_file, rom_file, pre_check["need_rom"]
                )
                if reload_result["device_reloading"]:
                    # Set reload timeout to 30 minutes
                    max_time = 1800.0
                    start_time = time.time()
                    # Wait for reload to complete. Initial ping set for 14 minutes.
                    # For testing, change reload time to 60 minutes and include command to cancel reload, then adjust this to a shorter wait.
                    time.sleep(840.0)
                    # Loops through pinging every minute after initial ping until max_time is reached.
                    while time.time() - start_time < max_time:
                        if ping(node_ip):
                            logger.info(
                                node_ip
                                + " is reachable again. Attempting to reconnect..."
                            )
                            break
                        # If initial ping fails, wait 60 seconds and try again.
                        else:
                            time.sleep(60.0)
                    # After max_time is reached, check if the node is back up. If not, add it to the failed_to_restore list.
                    else:
                        if ping(node_ip) is False:
                            print(f"{node_ip} did not reload in 30 minutes.")
                            logger.info(
                                node_ip
                                + " did not reload in 30 minutes. Added to failed_to_restore list."
                            )
                            failed_to_restore.append(node_ip)
                        else:
                            print(f"{list_1[i]} is reloaded and back up!")
                            logger.info(
                                node_ip
                                + "is reachable again. Attempting to reconnect..."
                            )
                    # Break out of loop on ring if node fails to restore. Don't break, in case error connecting not due to node being down.
                    if node_ip in failed_to_restore:
                        break
                    # Reconnect to device and run checks again.
                    else:
                        # Wait an additional 30 seconds before attempting to reconnect.
                        time.sleep(30.0)
                        print(f"{node_ip} reconnecting...")
                        # Skip post-checks and loop to second reload if workaround is needed.
                        if last_reload is False:
                            continue
                        else:
                            after_reload = True
                            # Collect dictionary of results from running checks.
                            post_check = run_checks(
                                device, ios_file, rom_file, after_reload
                            )
                            # If failed to connect to the node, add it to the nodes_down list.
                            if post_check is None:
                                nodes_down.append(node_ip)
                                logger.info(
                                    "Failed to reconnect to "
                                    + node_ip
                                    + ". Added to nodes_down list."
                                )
                                break
                            # Check if the upgrade was successful or not.
                            else:
                                logger.info(
                                    "Processing post-check results for "
                                    + node_ip
                                    + ": {}".format(post_check)
                                )
                                if (
                                    post_check["need_ios"] is True
                                    or post_check["need_rom"] is True
                                ):
                                    could_not_upgrade.append(post_check)
                                    logger.info(
                                        "Upgrade failed for "
                                        + node_ip
                                        + ". Added to could_not_upgrade list."
                                    )
                                    break
                                else:
                                    print(
                                        f"{post_check['node_name']} upgraded successfully!"
                                    )
                                    logger.info(
                                        post_check["node_name"]
                                        + " upgraded successfully!"
                                    )
                            # After processing last reload, set reload_flag to False.
                            reload_flag = False
                # If reload command shows failed but the ring is whole, see if
                # device is reachable and add to nodes_down list if not.
                # Otherwise add to could_not_upgrade list.
                else:
                    if reload_result["repair_path"] is False:
                        could_not_upgrade.append(pre_check)
                        logger.info(
                            node_ip
                            + " does not have a repair path. Added to could_not_upgrade list."
                        )
                        break
                    else:
                        logger.info("Failed to reload " + node_ip)
                        if ping(node_ip) is False:
                            print(f"{node_ip} is down!")
                            nodes_down.append(node_ip)
                            could_not_upgrade.append(pre_check)
                            break
                        else:
                            print(
                                f"{node_ip} is up but failed to reload properly."
                            )
                            could_not_upgrade.append(pre_check)
                            break
            # If device isn't ready for reload, add it to the could_not_upgrade list.
            # Can add logic to add nodes to lists based on what the issue is and then download files if needed.
            else:
                print(
                    f"{node_ip} failed pre-checks and may need to download upgrade files."
                )
                logger.info(
                    node_ip
                    + " failed pre-checks and may need to download upgrade files. Added to could_not_upgrade list."
                )
                could_not_upgrade.append(pre_check)
                break
    # Returns the lists of nodes that failed to upgrade, could not upgrade, and failed to restore.
    # Can create log files in the main function to store the lists.
    return (nodes_down, could_not_upgrade, failed_to_restore)


def main():
    """
    Executes the main function of the program.

    This function prompts the user to enter their username and password, and then uses the input to authenticate the user.
    It also calls the `list_append()` function to retrieve a list of devices to upgrade.
    The function then creates a thread pool executor with a maximum of 10 workers and maps the `upgrade()` function to each device in the `reload_list`.

    Parameters:
        None

    Returns:
        None
    """
    start_time = datetime.now()
    global username
    global password
    print("Enter your username:")
    username = input()
    print("Enter your password:")
    password = getpass.getpass()
    logger.info(f"User authenticated as {username}")
    logger.info("Retrieving list of devices to upgrade...")
    reload_list = list_append()
    max_workers = len(reload_list)
    # Initialize lists to capture upgrade results
    all_nodes_down = []
    all_could_not_upgrade = []
    all_failed_to_restore = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map upgrade function to devices and capture results
        results = executor.map(upgrade, reload_list)
        # Iterate through results and capture upgrade outcome for each device
        for result in results:
            nodes_down, could_not_upgrade, failed_to_restore = result
            all_nodes_down.extend(nodes_down)
            all_could_not_upgrade.extend(could_not_upgrade)
            all_failed_to_restore.extend(failed_to_restore)
    # Write results to log files
    end_time = datetime.now()
    write_to_log_file(devices_down_log, all_nodes_down)
    write_to_log_file(could_not_upgrade_log, all_could_not_upgrade)
    write_to_log_file(failed_to_restore_log, all_failed_to_restore)
    logger.info("Script execution completed.")
    logger.info(f"Script execution time: {end_time - start_time}")
    print("#" * 60)
    print("\n")
    print("Total time: {}".format(end_time - start_time))
    print("\n")


if __name__ == "__main__":

    # Ensure python 3.6 or higher is installed
    if not sys.version_info.major == 3 and sys.version_info.minor >= 6:
        print(
            "Your Python version is outdated and may not be compatible with this "
            "script."
        )
        print("Please consider updating Python to version 3.6 or later.")
        print(
            "You can download the latest version from: "
            "https://www.python.org/downloads/"
        )
        sys.exit(1)

    main()

quit()
