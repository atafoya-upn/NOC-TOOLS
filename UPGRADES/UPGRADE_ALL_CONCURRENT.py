#!/usr/bin/python3

import importlib.util
import os
import sys
import re
from getpass import getpass
from netmiko import ConnLogOnly, SSHDetect
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


class Router:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password


    @staticmethod
    def guess_dev_type(ip, username, password):
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
        return guesser.autodetect()


class ASR920(Router):
    
    def __init__(self, ip, username, password):
        super().__init__(ip, username, password)
        self.device = {
            "device_type": "ios-xe",
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
        }
        self.connection = ConnLogOnly(
            log_file="ASR920_session.log",
            log_level=10,
            log_format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            **self.device
            )


    def xe_device_info(self):

        try:
            #connect to device
            self.connection.establish_connection
            # Send commands to gather info
            running_cfg = self.connection.send_command(
                "show run", read_timeout=180
                )
            platform = self.connection.send_command(
                "show platform diag", use_textfsm=True, read_timeout=60
            )
            version = self.connection.send_command(
                "show version", use_textfsm=True, read_timeout=60
            )
            dest_directory = "bootflash:"
            dir_list = self.connection.send_command(
                f"dir {dest_directory}", read_timeout=120
            )
            net_ring = self.connection.send_command(
                "show snmp contact", read_timeout=120
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

            return {
                "host_name": host_name,
                "chassis": platform[0]["chassis_type"],
                "ios_ver": version[0]["version"],
                "rom_version": platform[0]["firmware_version"],
                "net_ring": net_ring,
                "ios_files": ios_files,
                "rom_files": rom_files,
            }
        except Exception as e:
            raise Exception(f"Failed to gather device info: {str(e)}") from e
    

    def verify_file(self, directory, file, checksum, file_list):
        """
        Verify the integrity of a file on a remote device.

        Args:
            connection (Connection): The connection object to the remote device.
            directory (str): The directory path on the remote device where the
                file is located.
            file (str): The name of the file to verify.
            checksum (str): The expected checksum of the file.
            file_list (list): A list of files present on the remote device.

        Returns:
            bool: True if the file is verified, False otherwise.

        Raises:
            None

        This function verifies the integrity of a file on a remote device by
        comparing its checksum with the expected checksum. It first checks if the
        file is present in the file_list. If it is not, it returns False.
        Otherwise, it constructs a command to verify the file's checksum and sends
        it to the remote device. If the output of the command contains the string
        'Verified', it returns True, indicating that the file is verified.
        Otherwise, it returns False. If the connection to the remote device is not
        active, it establishes a new connection before sending the command.
        """

        # Check for null pointer references
        if (
            self is None
            or directory is None
            or file is None
            or checksum is None
            or file_list is None
        ):
            raise ValueError(
                "verify_file: connection, directory, file, checksum, and file_list "
                "must not be None"
            )

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        if file not in file_list:
            return False
        cmd = f"verify /md5 {directory}{file} {checksum}"
        verify_con = self.is_alive()
        if verify_con is False:
            self.establish_connection()
        output = self.send_command(cmd, read_timeout=600)
        return "Verified" in output


    def run_checks(self):
        """
        Run checks before downloading files. Retrieves information about files,
        performs verifications, creates a dictionary with relevant device info,
        and removes unnecessary files if needed. Returns a dictionary containing
        various device details.
        """

        # Check for null pointer references
        if self is None:
            raise ValueError(
                "run_checks: connection must not be None"
            )

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        # Run checks before downloading files
        dest_dir = file_info["dest_directory"]
        platform = self.send_command(
            "show platform diag", use_textfsm=True, read_timeout=60
        )
        version = self.send_command("show version", use_textfsm=True, read_timeout=60)
        directory = self.send_command(f"dir {dest_dir}", read_timeout=60)
        node_name = version[0]["hostname"]
        ios_ver = version[0]["version"]
        running_image = version[0]["running_image"]
        rom_version = platform[0]["firmware_version"]
        bad_rom = file_info["bad_rom_list"]
        if rom_version in bad_rom:
            ios_file = file_info["workaround"]["file"]
            ios_current = file_info["workaround"]["version"]
            ios_md5 = file_info["workaround"]["checksum"]
        else:
            ios_file = file_info["ios"]["file"]
            ios_current = file_info["ios"]["version"]
            ios_md5 = file_info["ios"]["checksum"]
        ftp_dir = file_info["ftp_directory"]
        rom_file = file_info["rom"]["file"]
        rom_current = file_info["rom"]["version"]
        rom_md5 = file_info["rom"]["checksum"]
        # Check file list for any ios binary files
        ios_pattern = file_info["ios_pattern"]
        ios_re_pattern = re.compile(ios_pattern)
        ios_file_list = re.findall(ios_re_pattern, directory)
        pull_image_from_running = re.search(ios_re_pattern, running_image)
        running_image_m = pull_image_from_running.group()
        # Check file list for any rommon pkg files
        rom_pattern = file_info["rom_pattern"]
        rom_re_pattern = re.compile(rom_pattern)
        rom_file_list = re.findall(rom_re_pattern, directory)
        # List of files that are active or latest version
        file_list_keep = [
            file_info["ios"]["file"],
            file_info["workaround"]["file"],
            rom_file,
            running_image_m,
        ]
        # Combined list of ios and rom files in device directory
        file_list_check = [*ios_file_list, *rom_file_list]
        # List of ios or rom files not active or latest versions
        remove_list = Diff(file_list_keep, file_list_check)
        # Create formatted text for output to console
        text_list = [
            f"Running image: {running_image_m}",
            f"Keep list: {file_list_keep}",
            f"Files on device: {file_list_check}",
        ]
        # Remove unnecessary files to make room for new ios/rom files
        if remove_list != []:
            remove_notification = f"The following files will be removed from {node_name}:"
            text_list.append(remove_notification)
            for item in remove_list:
                text_list.append(item)
                del_cmds = [
                    f"delete {dest_dir}{item}",
                    "\n",
                    "\n",
                ]
                output = self.send_multiline_timing(del_cmds)
                logger.info(output)
            # Collect file list after removing unnecessary files
            directory = self.send_command(f"dir {dest_dir}", read_timeout=60)
            ios_file_list = re.findall(ios_re_pattern, directory)
            rom_file_list = re.findall(rom_re_pattern, directory)
        output_text = format_output_text(node_name, text_list)
        logger.info(output_text)
        # Verify integrity of ios and rom files
        if ios_file in ios_file_list:
            verify_ios = verify_file(self, dest_dir, ios_file, ios_md5, ios_file_list)
        else:
            verify_ios = False
        if rom_file in rom_file_list:
            verify_rom = verify_file(self, dest_dir, rom_file, rom_md5, rom_file_list)
        else:
            verify_rom = False
        # Create dictionary to return
        device_info = {
            "node_name": node_name,
            "ios_version": ios_ver,
            "rom_version": rom_version,
            "ios_current": ios_current,
            "rom_current": rom_current,
            "ftp_dir": ftp_dir,
            "dest_dir": dest_dir,
            "ios_file": ios_file,
            "rom_file": rom_file,
            "ios_md5": ios_md5,
            "rom_md5": rom_md5,
            "ios_file_list": ios_file_list,
            "rom_file_list": rom_file_list,
            "ios_file_verified": verify_ios,
            "rom_file_verified": verify_rom,
            "remove_list": remove_list,
        }
        self.disconnect()
        return device_info



    def file_download(self, source_dir, dest_dir, file, checksum):
        """
        Downloads a file from a remote host using the specified connection.

        Args:
            connection (Connection): The connection object to the remote host.
            source_dir (str): The directory path on the ftp server where the
                file is located.
            dest_dir (str): The directory path on the router where the file
                will be downloaded.
            file (str): The name of the file to download.
            checksum (str): The expected checksum of the downloaded file.

        Returns:
            bool: True if the file is successfully downloaded and verified,
                False otherwise.

        Raises:
            None

        This function establishes a connection to the remote host and attempts to
        download a file from the specified source directory. It uses the
        'copy http:' command to initiate the file transfer. The function retries
        the download up to three times if it fails to verify the downloaded file's
        checksum. If the download and verification are successful, the function
        returns True. Otherwise, it returns False. The function also measures the
        time taken to download the file and prints it.
        """

        # Check for null pointer references
        if self is None:
            raise ValueError(
                "file_download: connection must not be None"
            )

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        # Perform the file download
        cmd_list = [
            f"copy http: {dest_dir}",
            f"{ftp_server}",
            f"{source_dir}{file}",
            "\n",
            "\n",
        ]
        i = 0
        verified = False
        start_time = datetime.now()
        while i < 3 and not verified:
            try:
                self.establish_connection()
                output = self.send_multiline_timing(cmd_list, read_timeout=0)
                prompt = self.find_prompt()
                node_name = prompt.strip("#>")
                tqdm.write(f"{node_name} Downloading {file}... ")
                output += self.send_command_timing("\n", read_timeout=0)
                logger.info(output)
                if "bytes copied in" not in output:
                    raise Exception(f"!!!!!!Download failed for {node_name}!!!!!!")
            except Exception as e:
                logger.error(e)
                if "Not enough space on device" in output:
                    tqdm.write(
                        f"{node_name} Error: Not enough space on device. Flash may"
                        f" be failing on device."
                    )
                else:
                    tqdm.write(f"{node_name}: Error: {e}")
                last_output = get_last_two_lines(output)
                logger.error(last_output)
                i += 1
                continue
            try:
                verify_cmd = f"verify /md5 {dest_dir}{file} {checksum}"
                verify_output = self.send_command(verify_cmd, read_timeout=300)
                if "Verified" in verify_output:
                    verified = True
                    end_time = datetime.now()
                    time_diff = end_time - start_time
                    tqdm.write(f"{node_name} Time to download {file}: {time_diff}")
                    break
                else:
                    verified = False
                    i += 1
            except Exception as e:
                logger.error(e)
                self.establish_connection()
                i += 1
        self.disconnect()
        return verified


    def configure_boot(self, ios_file, rom_file, boot_conf_flag, rom_upgrade_flag):
        """
        Configures the boot settings for a device using the provided connection.

        Args:
            connection (object): The connection object to the device.
            ios_file (str): The name of the IOS file to configure.
            rom_file (str): The name of the ROM file to configure.
            boot_conf_flag (bool): Flag indicating whether to configure boot settings.
            rom_upgrade_flag (bool): Flag indicating whether to upgrade the ROM.

        Raises:
            Exception: If an error occurs while configuring the boot settings.

        Returns:
            None
        """
        # Check for null pointer references
        if self is None:
            raise ValueError(
                "configure_boot: connection must not be None"
            )

        # Check for unhandled exceptions
        if sys.exc_info()[0]:  # pylint: disable=unused-variable
            # If there are unhandled exceptions, print them
            exc = sys.exc_info()[1]  # pylint: disable=unused-variable
            tb = sys.exc_info()[2]  # pylint: disable=unused-variable
            traceback.print_exception(exc, exc.__dict__, tb)

        config = [
            "license accept end user agreement\n",
            "yes\n",
            "no boot system\n",
            f"boot system flash {ios_file}" + "\n",
        ]
        rom_cmd = f"upgrade rom-monitor filename bootflash:{rom_file} all"

        try:
            self.establish_connection()
            if boot_conf_flag:
                self.send_config_set(config, read_timeout=60, cmd_verify=False)
            if rom_upgrade_flag:
                self.send_command(rom_cmd, read_timeout=180)
            self.save_config()
        except Exception as e:
            logger.error(e)
        

    def download_process(self, progress_bar, lock):
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
        if self is None:
            raise ValueError(
                "download_process: list_of_devices must not be None"
            )

        # Iterate through the list of IP addresses and attempt to connect to each
        # device
        not_ready = []
        connection_failed = []
        devices_down = []
        post_checks = []
        x = len(self)
        for i in range(x):
            node_ip = self[i]
            tqdm.write(f"********{node_ip}********")
            try:
                # Setting the device info in thread local storage
                thread_local.device = node_ip
                logger.info(f"Connecting to {node_ip}")

                # Establish connection and raise exception if not reachable
                connection = device_connect(node_ip)
                if connection is None:
                    if is_reachable := ping(node_ip):
                        raise ConnectionError(f"{node_ip} is reachable but unable to connect.")
                else:
                    # Run pre-checks and initialize variables
                    pre_checks = run_checks(connection)
                    ios_file = pre_checks["ios_file"]
                    rom_file = pre_checks["rom_file"]

                    # Download IOS file if unable to verify file is on device
                    if pre_checks["ios_file_verified"] is False:
                        load_ios = file_download(
                            connection,
                            pre_checks["ftp_dir"],
                            pre_checks["dest_dir"],
                            pre_checks["ios_file"],
                            pre_checks["ios_md5"],
                        )
                        if load_ios is False:
                            boot_conf_flag = False
                            tqdm.write(f"{node_ip} failed to download ios file")
                            ios_ready = False
                        else:
                            # Send configuration commands and save running configuration
                            boot_conf_flag = True
                            tqdm.write(f"{ios_file} downloaded successfully on {node_ip}")
                            ios_ready = True
                    # If IOS is already on the device, just configure boot command
                    else:
                        boot_conf_flag = True
                        tqdm.write(f"{ios_file} already on {node_ip}")
                        ios_ready = True

                    # Download ROM file if unable to verify file is on device
                    if pre_checks["rom_file_verified"] is False:
                        load_rom = file_download(
                            connection,
                            pre_checks["ftp_dir"],
                            pre_checks["dest_dir"],
                            pre_checks["rom_file"],
                            pre_checks["rom_md5"],
                        )
                        if load_rom is False:
                            rom_upgrade_flag = False
                            tqdm.write(f"{node_ip} failed to download rom file")
                            rom_ready = False
                        else:
                            rom_upgrade_flag = True
                            tqdm.write(f"ROM file downloaded successfully on {node_ip}")
                            rom_ready = True
                    else:
                        rom_upgrade_flag = True
                        tqdm.write(f"{rom_file} already on {node_ip}")
                        rom_ready = True
                    if ios_ready and rom_ready:
                        configure_boot(connection, ios_file, rom_file, boot_conf_flag, rom_upgrade_flag)
                        tqdm.write(f"{node_ip} ready for upgrade!")
                    else:
                        tqdm.write(
                            f"!!!!!!Download failed for {node_ip}!!!!!!"
                            + "\nFiles not ready for upgrade. Check device and try again."
                        )
                        not_ready.append(pre_checks)
                    post_check = run_checks(connection)
                    post_checks.append(post_check)

            except ConnectionError as ce:
                tqdm.write(str(ce))
                connection_failed.append(node_ip)
                write_to_log_file(conn_failed_log, node_ip)
                logger.error(f"ConnectionError: {ce}")
            except Exception as e:
                # If there are unhandled exceptions, print them
                logger.error(f"Error with {node_ip}: {e}")
                logger.error(traceback.format_exc())
                continue
            except KeyboardInterrupt:
                tqdm.write("KeyboardInterrupt: Exiting program")
                exit(0)

            finally:
                # Thread-safe update of the progress bar
                with lock:
                    progress_bar.update(1)
        # Return results from each ring
        return (not_ready, connection_failed, devices_down, post_checks)


class ASR920Standard(ASR920):

    def __init__(self, connection):
        super().__init__(connection)
        self.ios = {
            "file": "asr920-universalk9_npe.16.12.06.SPA.bin",
            "version": "16.12.6",
            "checksum": "2dd77405109154cf224fcb4536264421",
        }
        self.rom = {
            "file": "asr920_15_6_48r_s_rommon.pkg",
            "version": "15.6(48r)S",
            "checksum": "4bbba2e41d832f5f4b3d3cf58dbb9f15",
        }
        self.workaround = {
            "file": "asr920-universalk9_npe.17.03.01.SPA.bin",
            "version": "17.3.1",
            "checksum": "bd8303eaf5a9a5b1db24e85a93b80cc6",
        }
        self.ftp_directory = "bootfiles/latest_ios_versions/"
        self.bad_rom_list = [
            "15.6(43r)S",
            "15.6(44r)S",
        ]


class ASR920_12SZ_IM(ASR920):

    def __init__(self, connection):
        super().__init__(connection)
        self.ios = {
            "file": "asr920igp-universalk9.16.06.06.SPA.bin",
            "version": "16.6.6",
            "checksum": "e2b66d2fcecbffcceeacbcb585bd4a29",
        }
        self.rom = {
            "file": "asr920_15_6_48r_s_rommon.pkg",
            "version": "15.6(48r)S",
            "checksum": "4bbba2e41d832f5f4b3d3cf58dbb9f15",
        }
        self.ftp_directory = "bootfiles/latest_ios_versions/"


class NCS540(Router):

    def __init__(self, ip, username, password):
        super().__init__(ip, username, password)
        self.device = {
            "device_type": "ios-xr",
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
        }
        self.connection = ConnLogOnly(
            log_file="NCS540_session.log",
            log_level=10,
            log_format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            **self.device
            )


    def xr_device_info(self):
        running_cfg = self.connection.send_command(
            "show run", read_timeout=180
        )
        platform = self.connection.send_command(
            "admin show platform", read_timeout=60
        )
        version = self.connection.send_command(
            "show version", read_timeout=60
        )
        dest_directory = "harddisk:"
        dir_list = self.connection.send_command(
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

        return {
            "hostname": host_name[1],
            "chassis": ch_re_pattern.search(platform)[1],
            "ios_ver": ver_re_pattern.search(version)[1],
            "dest_directory": dest_directory,
            "ios_files": ios_files,
            "rpm_files": rpm_files,
            "ios_pat": ios_pat,
            "rpm_pat": rpm_pat,
        }


    def download_file(self, file, file_md5, ftp_server, ftp_pass, ftp_path, sftp_path, destination_path):
        ftp_file_path = f"{ftp_server}{ftp_path}{file} {destination_path}"
        sftp_file_path = f"{ftp_server}{sftp_path}{file} {destination_path}"
        http_file_path = f""
        transfer_methods = ["ftp://", "http://", "https://", "sftp://", "scp://"]
        success = False

        try:
            self.establish_connection()

            for attempt in range(2):  # Loop twice
                for transfer_method in transfer_methods:
                    try:
                        if transfer_method.startswith("s"):
                            copy_cmd = [
                                f"copy {transfer_method}{sftp_file_path}",
                                ftp_pass,
                                "\n"
                            ]
                        elif transfer_method in ["http://", "https://"]:
                            copy_cmd = [
                                f"copy {transfer_method}{ftp_file_path}",
                                ftp_pass,
                                "\n"
                            ]
                        else:
                            copy_cmd = [
                                f"copy {transfer_method}{ftp_file_path}",
                                ftp_pass,
                                "\n"
                            ]

                        output = self.connection.send_multiline_timing(
                            copy_cmd,
                            read_timeout=2400
                        )

                        # Validate if the download was successful
                        if "Error" not in output:
                            print(f"Download succeeded with {transfer_method}")
                            success = True
                            break
                    except Exception as e:
                        print(f"Attempt {attempt + 1} with {transfer_method} failed: {str(e)}")

                if success:
                    break

            if not success:
                raise Exception("All download attempts failed.")

        except Exception as e:
            print(f"Failed to establish connection or download file: {str(e)}")
            success = False

        return success


class NCS540_28Z4C(NCS540):

    def __init__(self, connection):
        super().__init__(connection)
        self.current_version = "7.4.1"
        self.ios_7_3 = {
            "ftp_directory": "/latest_ios_versions/NCS540-28Z4C/7.3.1/",
            "http_directory": "/bootfiles/latest_ios_versions/NCS540-28Z4C/7.3.1/",
            "sftp_directory": ":/home/nde/latest_ios_versions/NCS540-28Z4C/7.3.1/",
            "file": "ncs540l-x64-7.3.1.iso",
            "checksum": "96d232153b4f3311e36110bef8588c82",
        }
        self.ios_7_4 = {
            "ftp_directory": "/latest_ios_versions/NCS540-28Z4C/7.4.1/",
            "sftp_directory": ":/home/nde/latest_ios_versions/NCS540-28Z4C/7.4.1/",
            "file": "ncs540l-x64-7.4.1.iso",
            "checksum": "11fd2da4f08876f66dc9bdbb6c5a920c",
        }


class NCS540X_6Z18G(NCS540):

    def __init__(self, connection):
        super().__init__(connection)
        self.current_version = "7.5.2"
        self.ftp_directory = "/latest_ios_versions/NCS540X-6Z18G-SYS/"
        self.sftp_directory = ":/home/nde/latest_ios_versions/NCS540X-6Z18G-SYS/"
        self.ios_7_3 = {
            "file": "ncs540l-aarch64-7.3.1.iso",
            "checksum": "71d01ab1511831f86608d516d6832ce0",
        }
        self.ios_7_5 = {
            "file": "ncs540l-aarch64-7.5.2.iso",
            "checksum": "264388ded888deecbe9098ed9c42644b",
        }


class NCS540_ACC(NCS540):

    def __init__(self, connection):
        super().__init__(connection)
        self.current_version = "7.4.2"
        self.ftp_server = f"{ftp_user}@{ftp_server}"
        self.ios_7_4 = {
            "ftp_directory": "/latest_ios_versions/NCS540-ACC-SYS/7.4.2/",
            "sftp_directory": ":/home/nde/latest_ios_versions/NCS540-ACC-SYS/7.4.2/",
            "files": {
                "ncs540-mini-x-7.4.2.iso": "9e87cb6eece22381ed98b03f4739b1b7",
                "ncs540-eigrp-1.0.0.0-r742.x86_64.rpm": "bb97f98c5473f9e23bf966db55a1969e",
                "ncs540-isis-1.0.0.0-r742.x86_64.rpm": "2209eae177462cc59ff319f3d094d2cf",
                "ncs540-k9sec-1.0.0.0-r742.x86_64.rpm": "cbe31c3dda425ad27b6cc82bd4635137",
                "ncs540-li-1.0.0.0-r742.x86_64.rpm": "5a50731a3aaf06fe5f6f797f23330a96",
                "ncs540-mcast-1.0.0.0-r742.x86_64.rpm": "8595afe195ab07e581f5644f732c28ea",
                "ncs540-mgbl-1.0.0.0-r742.x86_64.rpm": "ea2fc9d094cdf5b8118e36f8fce5506c",
                "ncs540-mpls-1.0.0.0-r742.x86_64.rpm": "0d062fc3db0d6ab4faa99ff82cca218a",
                "ncs540-mpls-te-rsvp-1.0.0.0-r742.x86_64.rpm": "901f78923bb7b65b9b947d26874987e8",
                "ncs540-ospf-2.0.0.0-r742.x86_64.rpm": "6fa0be1e410adaabdd0fb54d88025e73",
            },
        }


# Thread-local storage to keep track of device information
thread_local = threading.local()

# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define the log directory and log file path
log_dir = os.path.join(script_dir, 'logs')
log_file_path = os.path.join(log_dir, 'debug.log')
conn_failed_log = os.path.join(log_dir, 'dl_connection_failed.log')
devices_down_log = os.path.join(log_dir, 'dl_devices_down.log')
dev_info_log = os.path.join(log_dir, 'dev_info.log')

def setup_logger():
    """Set up the logging format and handler."""
    try:
        return log_settings()
    except Exception:
        tqdm.write("An unexpected error occurred while setting up the logger.")
        traceback.print_exc()
        raise


def log_settings():
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
    tqdm.write("netmiko is not installed. Would you like to install it now? (y/n)")
    choice = input().lower()
    if choice == "y":
        install_package("netmiko")
    else:
        tqdm.write(
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


# Function to get the terminal width
def get_console_width():
    
    return shutil.get_terminal_size().columns


# Function to format text with asterisks
def format_with_asterisks(node_name):
    
    console_width = get_console_width()
    total_stars = console_width - len(node_name)
    half_stars = total_stars // 2
    
    formatted_line = '*' * half_stars + node_name + '*' * half_stars
    
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

def run_options():
    
    option_list = [
        "Download upgrade files to device(s)",
        "Run upgrade on device(s)",
        "Download and then run upgrade(s)",
        ]
    
    while True:
        tqdm.write(
            "\nPlease select an option from the following list:\n"
            "1. Download upgrade files to device(s)\n"
            "2. Run upgrade on device(s)\n"
            "3. Download and then run upgrade(s)\n"
            "0. Exit\n\n"
            "Enter a number corresponding to your selection and press Enter.\n"
        )
        try:
            selection = int(input("Selection: "))
            if selection == 0:
                sys.exit(0)
            elif 1 <= selection <= 3:
                return selection
            else:
                tqdm.write("Invalid selection. Please try again.")
        except ValueError:
            tqdm.write("Invalid input. Please enter a number.")
            continue

def main():
    start_time = datetime.now()
    global username
    global password
    global ftp_user
    global ftp_pass
    global ftp_server
    print("Enter your username:")
    username = input()
    print("Enter your password:")
    password = getpass.getpass()
    reload_list = list_append()


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