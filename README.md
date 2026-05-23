# Netscan

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()

`Netscan` is a lightweight, high-performance network reconnaissance and discovery utility written in pure Python. It streamlines the network auditing process by executing asynchronous live-host discovery, port configuration analysis, and service mapping across specified subnets or IP ranges. 

Designed to be platform-independent and low-overhead, `Netscan` acts as a fast, scriptable alternative to heavy framework tools for quick security audits, internal topology mapping, and identifying unauthorized nodes on a local network subnet.

---

## 🚀 Features

* **Cross-Platform Compatibility:** Runs seamlessly across Windows, Linux, and macOS ecosystems with zero native OS binary dependencies.
* **Asynchronous Engine:** Optimized scanning architecture minimizing execution overhead and network latency delays.
* **Subnet & IP Range Discovery:** Broad targeting syntax supporting single host IPs, target lists, and standard CIDR notation blocks (e.g., `192.168.1.0/24`).
* **Port Verification:** Identifies exposed TCP/UDP ports, filtering out unresponsive states to isolate active surface vectors.
* **Clean Terminal Visualization:** Structured text outputs and diagnostic metrics engine for immediate structural tracking.

---

## 🛠️ Prerequisites

* **Python 3.8+** (Ensure Python is appended to your system's `PATH`)
* Administrative / Root Privileges (Required for socket binding operations during discovery raw-packet transmission)

---

## 📦 Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/BhargavA09/Netscan.git](https://github.com/BhargavA09/Netscan.git)
   cd Netscan
