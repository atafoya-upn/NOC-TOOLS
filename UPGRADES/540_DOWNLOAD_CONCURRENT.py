

import importlib.util
import os
import sys
import re
from getpass import getpass
from netmiko import ConnLogOnly
import signal
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading
import shutil
import traceback
import subprocess
import platform
from tqdm import tqdm


def get_file_list():
    """Get file list from device platforms through user input"""

    # Check for null pointer references
    device_platforms = {
        # "ASR920": {
            # "ios": {
                # "file": "asr920-universalk9_npe.16.12.06.SPA.bin",
                # "version": "16.12.6",
                # "checksum": "2dd77405109154cf224fcb4536264421",
            # },
            # "rom": {
                # "file": "asr920_15_6_48r_s_rommon.pkg",
                # "version": "15.6(48r)S",
                # "checksum": "4bbba2e41d832f5f4b3d3cf58dbb9f15",
            # },
            # "workaround": {
                # "file": "asr920-universalk9_npe.17.03.01.SPA.bin",
                # "version": "17.3.1",
                # "checksum": "bd8303eaf5a9a5b1db24e85a93b80cc6",
            # },
            # "ftp_directory": "bootfiles/latest_ios_versions/",
            # "dest_directory": "bootflash:",
            # "ios_pattern": r"asr920[.\w-]+bin",
            # "rom_pattern": r"asr920[.\w-]+pkg",
            # "bad_rom_list": [
                # "15.6(43r)S",
                # "15.6(44r)S",
            # ],
        # },
        # "ASR-920-12SZ-IM": {
        # 
        # },
        "NCS540-28Z4C": {
            "ios_7_3": {
                "file": "ncs540l-x64-7.3.1.iso",
                "version": "7.3.1",
                "checksum": "96d232153b4f3311e36110bef8588c82",
                "ftp_directory": "/latest_ios_versions/NCS540-28Z4C/7.3.1/",
            },
            "ios_7_5": {
                "file": "ncs540l-x64-7.5.2.iso",
                "version": "7.5.2",
                "checksum": "11fd2da4f08876f66dc9bdbb6c5a920c",
                "ftp_directory": "/latest_ios_versions/NCS540-28Z4C/7.5.2/",
            },
        },
        "NCS540X-6Z18G": {
            "ios_7_3": {
                "file": "ncs540l-aarch64-7.3.1.iso",
                "version": "7.3.1",
                "checksum": "71d01ab1511831f86608d516d6832ce0",
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

    # Check for unhandled exceptions
    if not isinstance(device_platforms, dict):
        raise ValueError("device_platforms is not a dictionary")

    dev_plat_keys = device_platforms.keys()
    while True:
        tqdm.write(
            "What device platform are you upgrading? Choose from the list "
            "below."
        )
        tqdm.write(
            "Only one device type can be upgraded through this script at a "
            "time."
        )
        for i, option in enumerate(dev_plat_keys, start=1):
            tqdm.write(f"{i}. {option}")
        try:
            number_of_platforms = len(dev_plat_keys)
            choice = int(
                input(
                    f"Enter the number of the platform you are upgrading "
                    f"(1-{number_of_platforms}): "
                )
            )
            if 1 <= choice <= number_of_platforms:
                dev_choice_key = list(dev_plat_keys)[choice - 1]
                return device_platforms[dev_choice_key]
            else:
                tqdm.write("Invalid choice. Please try again.")
        except ValueError:
            tqdm.write("Invalid input. Please enter a number.")
        except Exception:  # pylint: disable=broad-except
            # If an exception occurs during function execution, print the stack trace
            traceback.print_exc()
            continue


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
        ip_list = []

        # Get the IP addresses of the nodes in each ring
        for i in range(num_rings):
            nodes_in_ring = input(f"Enter number of nodes in ring{str(i)}: ")
            if nodes_in_ring is None:
                raise ValueError("nodes_in_ring is None")

            # Get the number of nodes in the current ring
            num_nodes_in_ring = int(nodes_in_ring)

            # Initialize the list to store the IP addresses of the nodes in the current ring
            ring_list = []

            # Get the IP addresses of the nodes in the current ring
            for j in range(num_nodes_in_ring):
                node_ip = input(f"Enter node{str(j)} IP: ")
                if node_ip is None:
                    raise ValueError("node_ip is None")

                # Append the IP address to the list
                ring_list.append(node_ip)

            # Append the list of IP addresses of the nodes in the current ring to the main list
            ip_list.append(ring_list)

        # Return the list of lists containing the IP addresses of the nodes
        return ip_list

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
        return [item for item in li2 if item not in li1]


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
            traceback.print_exception(exc, exc.__dict__, tb)

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


def device_connect(ip):
    """
    Connects to a device using the provided IP address and device parameters.
    Logs the connection details to 'file_transfer.log' with the specified log
    level and format. Returns the connection object.
    """

    # Check for null pointer references
    if ip is None or username is None or password is None:
        raise ValueError(
            "device_connect: IP, username, and password must not be None"
        )

    device = {
        "device_type": "cisco_xr",
        "ip": ip.strip(),
        "username": username,
        "password": password,
        "auto_connect": False,
        "fast_cli": False,
        "keepalive": 300,
        "timeout": 600,
        "session_timeout": 1800,
        "conn_timeout": 600,
        "banner_timeout": 300,
        "auth_timeout": 300,
        "blocking_timeout": 2400,
        "global_delay_factor": 2.0,
    }

    # Check for unhandled exceptions
    if sys.exc_info()[0]:  # pylint: disable=unused-variable
        # If there are unhandled exceptions, print them
        exc = sys.exc_info()[1]  # pylint: disable=unused-variable
        tb = sys.exc_info()[2]  # pylint: disable=unused-variable
        traceback.print_exception(exc, exc.__dict__, tb)

    return ConnLogOnly(
        **device,
    )

