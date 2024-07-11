#!/usr/bin/python3


import importlib.util
import sys
import re
from getpass import getpass
from netmiko import SSHDetect, ConnLogOnly
import signal
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading
import shutil
import traceback
import subprocess
import platform


class ConnectionError(Exception):
    pass

class UnreachableError(Exception):
    pass


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

# Thread-local storage to keep track of device information
thread_local = threading.local()

def setup_logger():
    """Set up the logging format and handler."""
    try:
        logger = logging.getLogger("NetmikoLogger")
        logger.setLevel(logging.DEBUG)

        # Create a file handler which logs even debug messages
        fh = logging.FileHandler('netmiko.log')
        fh.setLevel(logging.DEBUG)

        # Create a console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

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


# Function to check if a package is installed. Used for checking Netmiko.
def check_dependency(package_name):
    """
    Check if a package is installed.

    :param str package_name: Name of the package to check
    :return: bool Whether the package is installed or not
    """
    try:
        # Check for null pointer references
        if package_name is None:
            raise ValueError("package_name cannot be None")

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        # Check if the package is installed
        spec = importlib.util.find_spec(package_name)
        return spec is not None

    except Exception:  # pylint: disable=broad-except
        # If an exception occurs during checking, print the stack trace
        traceback.print_exc()


# Function to install a package using pip. Used to install Netmiko if
# dependency check fails.
def install_package(package_name):
    """Install a package using pip."""

    try:
        # Check for null pointer references
        if package_name is None:
            raise ValueError("package_name cannot be None")

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        # Install the package
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", package_name]
        )

    except Exception:  # pylint: disable=broad-except
        # If an exception occurs during installation, print the stack trace
        traceback.print_exc()


# Check if netmiko is installed
if not check_dependency("netmiko"):
    print("netmiko is not installed. Would you like to install it now? (y/n)")
    choice = input().lower()
    if choice == "y":
        install_package("netmiko")
    else:
        print(
            "netmiko is required for this script to run. Please install it and"
            " try again."
        )
        sys.exit(1)


# Function to handle graceful shutdown
def graceful_shutdown(signum, frame):
    """
    Handle graceful shutdown to prevent resource leaks and ensure smooth operation.

    :param int signum: Signal number
    :param object frame: Frame object
    """
    try:
        # Check for null pointer references
        if logger is not None:
            logger.info("Shutting down gracefully...")

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        # Exit gracefully
        sys.exit(0)

    except Exception:  # pylint: disable=broad-except
        # If an exception occurs during shutdown, print the stack trace
        traceback.print_exc()


# Register signal handlers for graceful shutdown
try:
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)
except AttributeError:
    logger.debug(
        "The 'signal' module is not available. Skipping signal handlers."
    )
except Exception:  # pylint: disable=broad-except
    # If an exception occurs during signal handler setup, print the stack trace
    traceback.print_exc()


# Function to write additional logs: nodes_down.log, could_not_upgrade.log,
# and failed_to_restore.log.
def write_to_log_file(file_path, data):
    """
    Writes a list of data to a file

    :param str file_path: Path to the file to write
    :param list data: List of data to write
    """
    try:
        if file_path is None:
            raise ValueError("file_path is None")

        if not isinstance(data, list):
            raise ValueError("data is not a list")

        with open(file_path, "a") as file:
            for item in data:
                try:
                    file.write(
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        + " - "
                        + str(item)
                        + "\n"
                    )
                except Exception:  # pylint: disable=broad-except
                    # If an exception occurs during writing to file, print the stack trace
                    traceback.print_exc()

    except Exception:  # pylint: disable=broad-except
        # If an exception occurs during function execution, print the stack trace
        traceback.print_exc()


# Function to get the terminal width
def get_console_width():
    
    return shutil.get_terminal_size().columns


# Function to format text with asterisks
def format_with_asterisks(identity):
    
    console_width = get_console_width()
    total_stars = console_width - len(identity)
    half_stars = total_stars // 2
    
    formatted_line = '*' * half_stars + identity + '*' * half_stars
    
    if total_stars % 2 != 0:
        formatted_line += '*'
    
    return formatted_line


# Function used to enclose device info between a line
# identifying the device and a full line of asterisks
def format_output_text(identity, string_list):
    
    top_line = format_with_asterisks(identity)
    bottom_line = '*' * get_console_width()

    output = f"\n\n{top_line}\n"
    for string in string_list:
        output += f"{string}\n"

    output += f"{bottom_line}\n\n"
    return output


def get_file_list(model):
    """Get file list from device platforms through user input"""

    # Check for null pointer references
    device_platforms = {
        "ASR920": {
            "ios": {
                "file": "asr920-universalk9_npe.16.12.06.SPA.bin",
                "version": "16.12.6",
                "checksum": "2dd77405109154cf224fcb4536264421",
            },
            "rom": {
                "file": "asr920_15_6_48r_s_rommon.pkg",
                "version": "15.6(48r)S",
                "checksum": "4bbba2e41d832f5f4b3d3cf58dbb9f15",
            },
            "workaround": {
                "file": "asr920-universalk9_npe.17.03.01.SPA.bin",
                "version": "17.3.1",
                "checksum": "bd8303eaf5a9a5b1db24e85a93b80cc6",
            },
            "ftp_directory": "bootfiles/latest_ios_versions/",
            "bad_rom_list": [
                "15.6(43r)S",
                "15.6(44r)S",
            ],
        },
        "ASR-920-12SZ-IM": {
            "ios": {
                "file": "asr920igp-universalk9.16.06.06.SPA.bin",
                "version": "16.6.6",
                "checksum": "e2b66d2fcecbffcceeacbcb585bd4a29",
            },
            "rom": {
                "file": "asr920_15_6_48r_s_rommon.pkg",
                "version": "15.6(48r)S",
                "checksum": "4bbba2e41d832f5f4b3d3cf58dbb9f15",
            },
            "ftp_directory": "bootfiles/latest_ios_versions/",
        },
        "NCS540-28Z4C": {
            "ios_7_3": {
                "file": "ncs540l-x64-7.3.1.iso",
                "version": "7.3.1",
                "checksum": "96d232153b4f3311e36110bef8588c82",
                f"ftp_directory": "://{ftp_user}@{ftp_server}/latest_ios_versions/NCS540-28Z4C/7.3.1/",
                f"sftp_directory": "://{ftp_user}@{ft_server}:/home/nde/latest_ios_versions/NCS540-28Z4C/7.3.1/"
            },
            "ios_7_4": {
                "file": "ncs540l-x64-7.4.1.iso",
                "version": "7.4.1",
                "checksum": "11fd2da4f08876f66dc9bdbb6c5a920c",
                "ftp_directory": "/latest_ios_versions/NCS540-28Z4C/7.4.1/",
            },
        },
        "NCS540X-6Z18G": {
            "ios_7_3": {
                "file": "ncs540l-aarch64-7.3.1.iso",
                "version": "7.3.1",
                "checksum": "71d01ab1511831f86608d516d6832ce0",
                "ftp_directory": "/latest_ios_versions/NCS540X-6Z18G-SYS/",
            },
            "ios_7_4": {
                "file": "ncs540l-aarch64-7.4.1.iso",
                "version": "7.4.1",
                "checksum": "c4964ade1f318fb2f8c81baafee1b022",
                "ftp_directory": "/latest_ios_versions/NCS540X-6Z18G-SYS/",
            },
            "ios_7_5": {
                "file": "ncs540l-aarch64-7.5.2.iso",
                "version": "7.5.2",
                "checksum": "264388ded888deecbe9098ed9c42644b",
                "ftp_directory": "/latest_ios_versions/NCS540X-6Z18G-SYS/",
            },
        },
        "NCS540-ACC": {
            "ios_7_4": {
                "file": "ncs540-mini-x-7.4.2.iso",
                "version": "7.4.2",
                "checksum": "9e87cb6eece22381ed98b03f4739b1b7",
                "ftp_directory": "latest_ios_versions/NCS540-ACC-SYS/7.4.2/",
                "eigrp_rpm": "ncs540-eigrp-1.0.0.0-r742.x86_64.rpm",
                "eigrp_checksum": "bb97f98c5473f9e23bf966db55a1969e",
                "isis_rpm": "ncs540-isis-1.0.0.0-r742.x86_64.rpm",
                "isis_checksum": "2209eae177462cc59ff319f3d094d2cf",
                "k9sec_rpm": "ncs540-k9sec-1.0.0.0-r742.x86_64.rpm",
                "k9sec_checksum": "cbe31c3dda425ad27b6cc82bd4635137",
                "li_rpm": "ncs540-li-1.0.0.0-r742.x86_64.rpm",
                "li_checksum": "5a50731a3aaf06fe5f6f797f23330a96",
                "mcast_rpm": "ncs540-mcast-1.0.0.0-r742.x86_64.rpm",
                "mcast_checksum": "8595afe195ab07e581f5644f732c28ea",
                "mgbl_rpm": "ncs540-mgbl-1.0.0.0-r742.x86_64.rpm",
                "mgbl_checksum": "ea2fc9d094cdf5b8118e36f8fce5506c",
                "mpls_rpm": "ncs540-mpls-1.0.0.0-r742.x86_64.rpm",
                "mpls_checksum": "0d062fc3db0d6ab4faa99ff82cca218a",
                "mpsl_te_rpm": "ncs540-mpls-te-rsvp-1.0.0.0-r742.x86_64.rpm",
                "mpsl_te_checksum": "901f78923bb7b65b9b947d26874987e8",
                "ospf_rpm": "ncs540-ospf-2.0.0.0-r742.x86_64.rpm",
                "ospf_checksum": "6fa0be1e410adaabdd0fb54d88025e73",
            },
        },
    }

    try:
        # Get model to match a key
        model = model.strip()
        if model.startswith("ASR-920"):
            if not model.endswith("12SZ-IM"):
                model = "ASR-920"
            else:
                model = model
        elif model.startswith("N540"):
            i = model.find("SYS")+3
            model = model[:i]
        else:
            raise ValueError(f"Invalid model: {model}")
        
        # Get the device platform from the model
        dev_plat = device_platforms[model]
        return dev_plat
    
    except ValueError:
        print(f"Invalid model: {model}")
    except Exception:  # pylint: disable=broad-except
        # If an exception occurs during function execution, print the stack trace
        traceback.print_exc()


def list_append():
    """
    A function that prompts the user to enter the number of rings and nodes
    in each ring. It then collects the IP addresses for each node and organizes
    them into a list of lists, where each inner list represents the nodes in a
    ring. Returns the list of lists containing the IP addresses of the nodes.
    """
    try:
        # Check for null pointer references
        ring_count = input("Enter number of rings: ")
        if ring_count is None:
            raise ValueError("ring_count is None")

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        # Get the number of rings
        num_rings = int(ring_count)

        # Initialize the list to store the IP addresses of the nodes
        list = []

        # Get the IP addresses of the nodes in each ring
        for i in range(0, num_rings):
            nodes_in_ring = input("Enter number of nodes in ring" + str(i) + ": ")
            if nodes_in_ring is None:
                raise ValueError("nodes_in_ring is None")

            # Get the number of nodes in the current ring
            num_nodes_in_ring = int(nodes_in_ring)

            # Initialize the list to store the IP addresses of the nodes in the current ring
            ring_list = []

            # Get the IP addresses of the nodes in the current ring
            for j in range(0, num_nodes_in_ring):
                node_ip = input("Enter node" + str(j) + " IP: ")
                if node_ip is None:
                    raise ValueError("node_ip is None")

                # Append the IP address to the list
                ring_list.append(node_ip)

            # Append the list of IP addresses of the nodes in the current ring to the main list
            list.append(ring_list)

        # Return the list of lists containing the IP addresses of the nodes
        return list

    except Exception:  # pylint: disable=broad-except
        # If an exception occurs during function execution, print the stack trace
        traceback.print_exc()
        return None


# Subtracting two lists
def Diff(li1, li2):
    """
    Subtracting two lists

    :param list li1: First list
    :param list li2: Second list
    :return: Difference between li1 and li2
    """
    try:
        # Check for null pointer references
        if li1 is None or li2 is None:
            raise ValueError(
                "li1 or li2 is None. One of the lists is not initialized."
            )

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        # Calculate the difference
        result = [item for item in li2 if item not in li1]
        return result

    except Exception:  # pylint: disable=broad-except
        # If an exception occurs during function execution, print the stack trace
        traceback.print_exc()
        return None


def get_last_two_lines(text):
    """
    Get the last two lines of text.

    :param str text: Text to split
    :return: List of the last two lines, or just the last line if there is only one line, or an empty list if there are no lines
    """
    try:
        # Check for null pointer references
        if text is None:
            raise ValueError("text is None")

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, tb)

        # Split the text into lines
        lines = text.splitlines()

        # Return the last two lines, or just the last line if there is only one line, or an empty list if there are no lines
        if len(lines) >= 2:
            return lines[-2:]
        elif lines:
            return lines[-1:]
        return []

    except Exception:  # pylint: disable=broad-except
        # If an exception occurs during function execution, print the stack trace
        traceback.print_exc()
        return []


def ping(host):
    """
    A function that checks if a host is pingable.
    It uses the ping command with the -n flag for Windows and -c for Linux.

    Args:
        host (str): The IP address of the host to ping.

    Returns:
        bool: True if the host is pingable, False otherwise.
    """
    try:
        # Check for null pointer references
        if host is None:
            raise ValueError("host cannot be None")

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        # Determine the ping command based on the operating system
        param = "-n" if platform.system().lower() == "windows" else "-c"
        count = "1" if platform.system().lower() == "windows" else "5"

        # Build the ping command
        command = ["ping", param, count, host]

        # Execute the ping command
        try:
            output = subprocess.check_output(
                command, universal_newlines=True, stderr=subprocess.STDOUT
            )
        except subprocess.CalledProcessError:
            # If the ping command fails, it will raise a CalledProcessError
            return False

        # Check for specific undesirable output
        if "TTL expired in transit" in output:
            return False

        # Check if there are any replies indicating success
        if "Reply from" in output or "bytes from" in output:
            return True

    except Exception:  # pylint: disable=broad-except
        # If an exception occurs during function execution, print the stack trace
        traceback.print_exc()
        return False

    return False


def guess_dev_type(ip):
    """
    Connects to a device using the provided IP address and device parameters.
    Automatically detects the device type based on the SSH connection.

    Parameters:
        ip (str): The IP address of the device.

    Returns:
        str: The best match device type based on the SSH connection.
    """

    device = {
        "device_type": "autodetect",
        "ip": ip,
        "username": username,
        "password": password,
    }

    guesser = SSHDetect(**device)
    best_match = guesser.autodetect()

    return best_match


def device_connect(ip, device_type):
    """
    Connects to a device using the provided IP address and device parameters.

    Args:
        ip (str): The IP address of the device.
        device_type (str): The type of the device.

    Returns:
        ConnLogOnly: A connection object to the device.

    This function creates a device dictionary with the provided IP address,
    device type, username, password, and various connection parameters. It
    then creates a connection object using the ConnLogOnly class, passing in
    the device dictionary and logging parameters. The connection object is
    then returned.
    """

    device = {
        "device_type": device_type,
        "ip": ip,
        "username": username,
        "password": password,
        "auto_connect": False,
        "fast_cli": False,
        "keepalive": 30,
        "session_timeout": 1800,
        "conn_timeout": 300,
        "banner_timeout": 180,
        "auth_timeout": 180,
        "blocking_timeout": 2400,
        "global_delay_factor": 2.0,
        "session_log_file_mode": "write",
    }

    connection = ConnLogOnly(
        log_file="GET_CKIDs_errors.log",
        log_level=logging.ERROR,
        log_format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        **device,
    )

    return connection


def xe_device_info(connection):

    # Send commands to gather info
    running_cfg = connection.send_command(
        "show run", read_timeout=180
        )
    platform = connection.send_command(
        "show platform diag", use_textfsm=True, read_timeout=60
    )
    version = connection.send_command(
        "show version", use_textfsm=True, read_timeout=60
    )
    dest_directory = "bootflash:"
    dir_list = connection.send_command(
        f"dir {dest_directory}", read_timeout=120
    )

    # Define regex patterns and compile them
    ios_pattern = r"asr920[.\w-]+bin",
    ios_pat = re.compile(ios_pattern)
    rom_pattern = r"asr920[.\w-]+pkg",
    rom_pat = re.compile(rom_pattern)
    hostname_pat = r"(?:hostname\s+\b)([-\w]+\b)"
    host_pat = re.compile(hostname_pat)
    
    # Extract hostname from running configuration
    host_name = host_pat.search(running_cfg)
    # Extract ios/rom files from directory
    ios_files = ios_pat.findall(dir_list)
    rom_files = rom_pat.findall(dir_list)

    device_info = {
        "hostname": host_name.group(1),
        "chassis": platform[0]["chassis_type"],
        "ios_ver": version[0]["version"],
        "rom_version": platform[0]["firmware_version"],
        "dest_directory": dest_directory,
        "ios_files": ios_files,
        "rom_files": rom_files,
        "ios_pat": ios_pat,
        "rom_pat": rom_pat,
    }

    return device_info


def xr_device_info(connection):

    # Send commands to gather info
    running_cfg = connection.send_command(
        "show run", read_timeout=180
        )
    platform = connection.send_command(
        "admin show platform", read_timeout=60
    )
    version = connection.send_command(
        "show version", read_timeout=60
    )
    dest_directory = "harddisk:"
    dir_list = connection.send_command(
        f"dir {dest_directory}", read_timeout=120
    )

    # Define regex patterns and compile them
    hostname_pat = r"(?:hostname\s+\b)([-\w]+\b)"
    host_pat = re.compile(hostname_pat)
    ch_pattern = r"(N540X?-[A26][C8Z][CZ1][48]?[CG]?-SYS-?[AD]?)"
    ch_re_pattern = re.compile(ch_pattern)
    ver_pattern = r"(?:\s+Version\s+\:\s)(\d\.\d\.\d)"
    ver_re_pattern = re.compile(ver_pattern)
    ios_pattern = r"ncs540[-\w]+[.\d]+iso"
    ios_pat = re.compile(ios_pattern)
    rpm_pattern = r"ncs540-[a-z]+-[.\d]+-r\d+\.x86_64\.rpm"
    rpm_pat = re.compile(rpm_pattern)
    # Extract hostname from running configuration
    host_name = host_pat.search(running_cfg)
    # Extract ios files from directory
    ios_files = ios_pat.findall(dir_list)
    rpm_files = rpm_pat.findall(dir_list)

    device_info = {
        "hostname": host_name.group(1),
        "chassis": ch_re_pattern.search(platform).group(1),
        "ios_ver": ver_re_pattern.search(version).group(1),
        "dest_directory": dest_directory,
        "ios_files": ios_files,
        "rpm_files": rpm_files,
        "ios_pat": ios_pat,
        "rpm_pat": rpm_pat,
    }

    return device_info


def download_process(list_of_devices):
    """
    Downloads files from a list of devices.

    Args:
        list_of_devices (list): A list of IP addresses of the devices to
            download files from.

    Returns:
        tuple: A tuple containing two lists. The first list contains the
            pre-checks that failed for each device, and the second list
            contains the IP addresses of devices that failed to connect.
    """

    # Check for null pointer references
    if list_of_devices is None:
        raise ValueError(
            "download_process: list_of_devices must not be None"
        )

    # Iterate through the list of IP addresses and attempt to connect to each
    # device
    not_ready = []
    connection_failed = []
    devices_down = []
    post_checks = []
    x = len(list_of_devices)
    for i in range(x):
        node_ip = list_of_devices[i]
        print(f"********{node_ip}********")
        try:
             # Setting the device info in thread local storage
            thread_local.device = node_ip
            logger.info(f"Connecting to {node_ip}")

            # Get the best match device type based on the SSH connection
            ios_type = guess_dev_type(node_ip)
            connection = device_connect(node_ip, ios_type)

            # Gather device info based on ios_type
            if ios_type == "cisco_xe":
                device_info = xe_device_info(connection)
            elif ios_type == "cisco_xr":
                device_info = xr_device_info(connection)
            else:
                print(
                    "Device is not a supported model\n" \
                    f"Device type: {ios_type}"
                    )
                continue
            file_info = get_file_list(device_info["chassis"])
            if file_info is None:
                raise ValueError("file_info must not be None")
            


def main():
    
    start_time = datetime.now()
    # Get the username and password from the user
    global username
    global password

    print("Enter your username:")
    if input_username := input("Username: "):
        username = input_username
    else:
        raise ValueError("username must not be empty")

    print("Enter your password:")
    if input_password := getpass():
        password = input_password
    else:
        raise ValueError("password must not be empty")
    
    if username is None or password is None:
        raise ValueError("username and password must not be None")

    # Get the list of ASR-920 IP addresses from the user
    router_list = list_append()
    if not router_list:
        raise ValueError("router_list must not be empty")
    max_workers = len(router_list)
    
    all_not_ready = []
    all_connection_failed = []
    all_devices_down = []
    all_device_info = []
    console_width = shutil.get_terminal_size().columns
    line_sep = "*" * console_width

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map upgrade function to devices and capture results
        try:
            results = executor.map(download_process, router_list)
        except Exception as e:
            # If there are unhandled exceptions, print them
            logger.error(f"An error occurred in main: {e}")
            logger.error(traceback.format_exc())  # Log the full traceback
            raise

        # Iterate through results and capture upgrade outcome for each device
        for result in results:
            # Unpack results
            not_ready, connection_failed, devices_down, post_check = result
            if not_ready is None:
                raise ValueError("not_ready must not be None")
            if connection_failed is None:
                raise ValueError("connection_failed must not be None")
            if devices_down is None:
                raise ValueError("devices_down must not be None")
            if post_check is None:
                raise ValueError("post_check must not be None")
            all_not_ready.extend(not_ready)
            all_connection_failed.extend(connection_failed)
            all_devices_down.extend(devices_down)
            all_device_info.append(post_check)

    print(all_not_ready)
    print(all_connection_failed)
    print(all_devices_down)
    write_to_log_file("device_info.log", all_device_info)

    print(f"Elapsed time: {datetime.now() - start_time}")



if __name__ == "__main__":
    main()

quit()