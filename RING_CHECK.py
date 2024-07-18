
import sys
from getpass import getpass
from netmiko import ConnectHandler
from netmiko import ConnectionException
import re


def device_connect(ip, username, password):
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
        "device_type": "cisco_xe",
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
        "session_log_file_mode": "write",
        }

    net_connect = ConnectHandler(
        **device,
        )

    return net_connect


def ring_check(connection):
    """
    Checks if the ring is in duplex mode by verifying if the OSPF border-routers have a repair path.

    Args:
        connection (object): The connection object used to send commands to the device.

    Returns:
        bool: True if the ring is in duplex mode, False otherwise.
    """
    
    if connection is None:
        raise ConnectionException(
            "Connection Failed!"
        )
    # Connect to device
    connection.establish_connection()
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
            return False


def main():
    print("Enter your username:")
    username = input("Username: ")
    print("Enter your password:")
    password = getpass(prompt='Password: ')
    print("Enter IP for device on the ring you are checking:")
    device_ip = input("IP: ")

    try:
        connection = device_connect(device_ip, username, password)
        print("Connecting to device and checking ring status...")
        if ring_check(connection):
            print("Ring is whole")
        else:
            print("Ring is in simplex!!!")
    except:
        raise ConnectionException()


if __name__ == "__main__":

    # Ensure python 3.6 or higher is installed
    if sys.version_info.major != 3 and sys.version_info.minor >= 6:
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