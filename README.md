# NOC-TOOLS

## Overview
Main directory for the noc-tools project. Currently includes a script for collecting circuit IDs from production devices and a directory for scripts used in upgrading devices.

---

## Scripts Included

### 🧰 `Get_CKIDs.py`
**Version:** 5.0
**Purpose:**
Used for collecting information from specified devices that are expected to be impacted by maintenance work. Gathers all the CKSIDs in the form of XXXXXXXX/XXXXXX/XXXXXXXX or XXXXXXXX-XXXXXX-XXXXXXXX listed in the configurations on any of our current Cisco routers. The market will still need to provide an impact list for any core equipment, as they are likely to affect services not explicitly listed in configuration files.

# Cisco ASR-920 Bulk Upgrade Automation

## Overview
This project provides two coordinated Python scripts for automating **bulk software upgrades** of Cisco ASR-920 routers in a production environment.  
They streamline image downloads, upgrade execution, and validation tasks — supporting concurrent operations, centralized logging, and graceful interruption handling.

These scripts are designed for use by network engineers performing controlled upgrade cycles across access or aggregation rings.

---

## Scripts Included

### 🧰 `920_DOWNLOAD_CONCURRENT.py`
**Version:** 3.0  
**Purpose:**  
Performs **parallel image downloads** to multiple ASR-920 routers to pre-stage firmware prior to upgrades.

**Key Features**
- Prompts for authentication credentials and device IPs interactively (with optional `.env` overrides).  
- Uses Python’s `ThreadPoolExecutor` for **concurrent transfers**.  
- Executes pre-checks and post-checks to validate file presence and integrity.  
- Displays **progress bars** via `tqdm`.  
- Logs all activity and gracefully handles interruptions (`Ctrl+C`).  
- Verifies dependencies (`Netmiko`, `tqdm`, `python-dotenv`) and assists in installation if missing.

---

### ⚙️ `920_UPGRADE_CONCURRENT.py`
**Version:** 3.0  
**Purpose:**  
Automates **sequential device upgrades** for Cisco IOS-XE (ASR-920) routers — upgrading one device per ring to maintain service continuity.

**Key Features**
- Automatically authenticates and connects to target devices via Netmiko.  
- Runs **pre-upgrade checks**, triggers the upgrade, and performs **post-upgrade validation**.  
- Provides error-resilient logging, thread control, and graceful shutdowns.  
- Includes dependency checks and user prompts for missing packages.

---

## Requirements

- **Python 3.9+**
- External packages:
  - [`netmiko`](https://pypi.org/project/netmiko/) – SSH connection automation  
  - [`tqdm`](https://pypi.org/project/tqdm/) – Progress bar utility  
  - [`python-dotenv`](https://pypi.org/project/python-dotenv/) – Environment variable loader  

---

## Installation

1. **Clone or copy** this project to your local environment.

2. (Optional) Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate       # macOS/Linux
   .venv\Scripts\activate          # Windows
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Place your `.env` file** in the main directory (...\noc-tools\)

---

## Environment Configuration (`.env`)

> The scripts **prompt interactively** for anything not provided in `.env`.  
> At runtime, you will also be asked to **choose an environment profile**:  
> **ENTER** → generic defaults, **1** → **production**, **2** → **provisioning**.

### Generic (fallback) values
These are used when no profile-specific override is set:
```env
FTP_SERVER=10.0.0.1          # IP address (v4 or v6)
FTP_USER=ftpuser
FTP_PASSWORD=changeme

DEVICE_USERNAME=             # optional; if blank you'll be prompted
DEVICE_PASSWORD=
```

### Optional profile-based overrides
If you choose **Production** at the prompt, the script prefers `*_PROD`;  
if you choose **Provisioning**, it prefers `*_PROV`. Missing values fall back to the generic keys above, then to interactive prompts.
```env
# Production overrides (optional)
FTP_SERVER_PROD=10.0.0.2
FTP_USER_PROD=
FTP_PASSWORD_PROD=

DEVICE_USERNAME_PROD=
DEVICE_PASSWORD_PROD=

# Provisioning overrides (optional)
FTP_SERVER_PROV=10.10.0.10
FTP_USER_PROV=
FTP_PASSWORD_PROV=

DEVICE_USERNAME_PROV=
DEVICE_PASSWORD_PROV=
```

### Other optional settings (not currently used in any scripts)
```env
# Directory for saving logs and reports (default: logs/)
LOG_PATH=logs/

# Optional device list file
DEVICE_LIST=data/devices.txt
```

> 🔒 **Security note:** Never commit `.env` with secrets to version control. Add `.env` to `.gitignore` and ship a `.env.example` without secrets.

---

## Usage

### 1. Pre-stage device images
```bash
python 920_DOWNLOAD_CONCURRENT.py
```
You will see:
```
Select environment profile:
  1. Production
  2. Provisioning
  (Press ENTER to use generic defaults)
Enter choice [1/2 or ENTER]:
Enter number of rings: 
Enter number of nodes in ring0:
Enter node0 IP: 
Enter node1 IP: 
...
Enter number of nodes in ring1: 
...
********ring0node0IP********
********ring0node1IP********
********ring0node2IP********
********ring0node3IP********
...
```
A progress bar at the bottom will show the progress of the script.

### 2. Execute upgrades sequentially by ring
```bash
python 920_UPGRADE_CONCURRENT.py
```

**Notes:**
- Devices can be entered manually or loaded from a file.  
- Progress and status will be shown for each device.  
- Logs are written to the directory defined in `LOG_PATH` (default: `logs/`).  

---

## Logging and Output

- Each run generates timestamped logs (e.g. `upgrade_2025-10-06.log`).  
- Logs capture authentication, file transfer status, success/failure flags, and exceptions.  
- Console output shows summarized progress with color-coded status indicators if supported.

---

## Graceful Shutdown

Both scripts trap `SIGINT` (Ctrl+C).  
If interrupted:
- Active SSH sessions are closed cleanly.  
- Partially completed device tasks are logged.  
- Threads are safely terminated without leaving orphaned processes.

---

## Common Errors & Troubleshooting

| Issue | Possible Cause | Resolution |
|-------|----------------|-------------|
| **`ModuleNotFoundError: No module named 'netmiko'`** | Dependency not installed | Run `pip install -r requirements.txt` |
| **Invalid FTP IP** | `FTP_SERVER` not an IP address | Use a valid IPv4/IPv6 address or re-enter when prompted |
| **Authentication failures** | Wrong username/password or creds unset | Provide in `.env` or re-enter at prompt |
| **Timeouts during file transfer** | Slow network / unreachable host | Verify connectivity or adjust thread count if applicable |
| **`OSError: [Errno 24] Too many open files`** | Too many parallel SSH sessions | Reduce concurrency level in script configuration |

---

## Best Practices

- Run during approved maintenance windows.  
- Test on a lab ring before production execution.  
- Maintain an offline copy of current firmware images.  
- Always back up configurations before starting bulk upgrades.  
- Review log output after each operation.

---

## Author
**Adam Tafoya**

---

## License
This project is provided for internal network automation use.  
No warranty is expressed or implied. Use at your own risk.
