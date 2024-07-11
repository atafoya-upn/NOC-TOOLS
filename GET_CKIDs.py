#!/usr/bin/python3

###############################################################################
#   GET_CKIDs.py Ver 4.0                                                        #
#   Author: Adam Tafoya                                                       #
# Dependencies:                                                               #
#   Netmiko, getpass, datetime, logging, re                                   #
# Script Description:                                                         #
#   This Python script collects circuit IDs from a list of network devices    #
#   provided by the user. The script prompts the user for authentication      #
#   credentials and IP addresses of the devices. It then detects the type of  #
#   each device, establishes an SSH connection, and executes commands to      #
#   retrieve configuration information. The script parses this information to #
#   extract the hostname and circuit IDs, which are printed in a structured   #
#   format. This information is useful for planning maintenances and          #
#   notifying customers. Error handling and logging are integrated to ensure  #
#   reliability and aid in troubleshooting.                                   #
###############################################################################

import re
from getpass import getpass
from netmiko import SSHDetect, ConnLogOnly
from datetime import datetime
import logging
import shutil


def get_list_of_devices():
    """
    Prompts the user to enter a list of IP addresses, each on a new line. The user
    can enter as many IP addresses as they want and then press Enter on an empty line
    to indicate that they are done. The function returns a list of the IP addresses
    entered by the user.

    Returns:
        list: A list of strings representing the IP addresses entered by the user.
    """

    print("Enter the list of IP addresses, each on a new line.")
    print("When you are done, enter an empty line and press Enter.")
    list_of_devices = []
    while True:
        ip = input()
        if ip.strip():
            list_of_devices.append(ip.strip())
        else:
            break

    # Clear the screen after getting the list of devices
    print("\033[2J\033[H", end="", flush=True)

    return list_of_devices


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

    platform = connection.send_command(
        "show platform diag", use_textfsm=True, read_timeout=60
    )
    version = connection.send_command(
        "show version", use_textfsm=True, read_timeout=60
    )
    device_info = {
        "chassis": platform[0]["chassis_type"],
        "ios_ver": version[0]["version"],
        "rom_version": platform[0]["firmware_version"],
    }

    return device_info

def xr_device_info(connection):

    platform = connection.send_command(
        "admin show platform", read_timeout=60
    )
    version = connection.send_command(
        "show version", read_timeout=60
    )
    ch_pattern = r"(N540X?-[A26][C8Z][CZ1][48]?[CG]?-SYS-?[AD]?)"
    ch_re_pattern = re.compile(ch_pattern)
    ver_pattern = r"(?:\s+Version\s+\:\s)(\d\.\d\.\d)"
    ver_re_pattern = re.compile(ver_pattern)


    device_info = {
        "chassis": ch_re_pattern.search(platform).group(1),
        "ios_ver": ver_re_pattern.search(version).group(1),
    }

    return device_info


def get_ckids(connection):
    """
    Retrieves information from a network device using the provided connection.
    
    Args:
        connection (object): The connection object to the network device.
        
    Returns:
        dict: A dictionary containing the hostname and circuit IDs gathered from the device.
            The dictionary has the following structure:
            {
                "Hostname": str,
                "Circuit_IDs": list
            }
            If an error occurs during the process, an exception is raised and the error message is printed.
    """

    # Define regex patterns and compile them
    hostname_pat = r"(?:hostname\s+\b)([-\w]+\b)"
    host_pat = re.compile(hostname_pat)
    circuit_pat = r"([A-Z]{6}\w{2}[-/][A-Z]{3}\w{3}[-/][A-Z]{6}\w{2})"
    c_pat = re.compile(circuit_pat)
    voice_pat = r"(?:description.*)(WL.?[0-9]{5})"
    v_pat = re.compile(voice_pat)

    # Define commands
    config_cmd = r"sh run"
    voice_cmd = r"sh ip route vrf VOICE | i directly connected"

    try:

        # Establish connection
        connection.establish_connection()
        # Send commands
        running_cfg = connection.send_command(config_cmd)
        voice_check = connection.send_command(voice_cmd)
        # Disconnect
        connection.disconnect()

        # Extract hostname and circuit IDs from running configuration
        host_name = host_pat.search(running_cfg)
        ckids = c_pat.findall(running_cfg)
        # Remove dashes from circuit IDs
        updated_list = [s.replace("-", "/") for s in ckids]
        # Remove duplicates
        circuit_ids = list(set(updated_list))
        # Check if voice circuit is present
        if 'directly connected' in voice_check:
            circuit_ids.extend(v_pat.findall(running_cfg))

        # Create a dictionary with hostname and circuit IDs
        gathered_info = {
            "Hostname": host_name.group(1),
            "Circuit_IDs": circuit_ids,
        }

        return gathered_info

    except Exception as e:
        print(e)


def main():
    """
    Executes the main function of the program.

    This function prompts the user to enter their username and password, and
    then uses the input to authenticate the user. It also retrieves a list of
    ASR-920 IP addresses from the user and gathers device information for
    each router in the list. The device information includes the hostname and
    circuit IDs of each router. The function uses multithreading to speed up
    the process and displays the hostname and circuit IDs for each router. If
    an exception occurs during the process, the error message is printed.

    Parameters:
        None

    Returns:
        None
    """

    start_time = datetime.now()
    # Get the username and password from the user
    global username
    global password
    print("Enter your username:")
    username = input("Username: ")
    print("Enter your password:")
    password = getpass()
    # Get the list of ASR-920 IP addresses from the user
    list_of_devices = get_list_of_devices()
    print("Gathering device information...")
    ckid_full_list = []
    console_width = shutil.get_terminal_size().columns
    for router in list_of_devices:
        try:
            # Get the best match device type based on the SSH connection
            ios_type = guess_dev_type(router)
            connection = device_connect(router, ios_type)

            # Gather device info based on ios_type
            if ios_type == "cisco_xe":
                device_info = xe_device_info(connection)
                formatted_info = f"Chassis: {device_info['chassis']} - " \
                    f"IOS: {device_info['ios_ver']} - " \
                    f"ROMMON: {device_info['rom_version']}"
            elif ios_type == "cisco_xr":
                device_info = xr_device_info(connection)
                formatted_info = f"Chassis: {device_info['chassis']} - " \
                    f"IOS: {device_info['ios_ver']}"
            else:
                print(
                    "Device is not a supported model\n" \
                    f"Device type: {ios_type}"
                    )
                continue
            
            # Gather circuit IDs    
            collected_info = get_ckids(connection)
            # Create a formatted string listing hostname and circuit IDs.
            # This allows the ckids to be displayed under the correct hostname
            # in case multithreading is used to speed up the script.
            formatted_ckids = "\n".join(
                f"{item}" for item in collected_info["Circuit_IDs"]
            )
            info_header = f"* {router} - {collected_info['Hostname']} - " \
                f"{formatted_info} *"
            stars = "*" * len(info_header)
            
            print(
                f"\n{stars}\n{info_header}\n{stars}\n{formatted_ckids}"
            )

            ckid_full_list.extend(collected_info["Circuit_IDs"])

        except Exception as e:
            print(e)

    line_sep = "*" * console_width
    print(f"\n\n{line_sep}\n\nCKID List: ")
    print(*ckid_full_list, sep="\n")
    print("\n\nTime taken: ", datetime.now() - start_time)
    print("\n")
    print("*" * console_width)


if __name__ == "__main__":
    main()
