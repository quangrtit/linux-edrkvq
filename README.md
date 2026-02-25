# Linux Behavior Blocking Module (eBPF-based EDR)

This project focuses on researching and developing an Endpoint Detection and Response (EDR) module for Linux. By leveraging the power of **eBPF (Extended Berkeley Packet Filter)** and **LSM (Linux Security Modules)**, the system provides real-time monitoring and blocking of malicious behaviors with high performance and minimal system impact.

## Key Features

The module is divided into two main functional areas:

### 1. Self-Defense

Protects the EDR agent itself and critical system resources from being tampered with by malware or unauthorized users.

* **File Protection**: Prevents unauthorized deletion, modification, renaming, or permission changes (`chmod`) of protected files.

* **Process Protection**: Safeguards processes from being killed, injected with code, or having their CPU/IO priorities lowered.
 
* **Module Loading Control**: Blocks the loading of unauthorized kernel modules to prevent backdoors.

### 2. IOC (Indicator of Compromise) Blocking

Real-time blocking of known threats based on established security policies and databases.

* **Malicious Executable Blocking**: Uses `fanotify` and eBPF hooks (e.g., `lsm/bprm_creds_from_file`) to intercept file execution. It supports blocking both on-disk files and fileless execution (via `memfd_create`).

* **Network Blocking**: Utilizes **XDP (Express Data Path)** to drop packets from known malicious IP addresses at the earliest possible stage in the network stack.

## System Architecture

The project follows a hybrid architecture combining user-space management and kernel-space enforcement:

* **User-space (Sentinel EDR Agent)**:
* Manages policies via JSON configuration files.


* Handles IOC databases using **LMDB** for high-speed lookups.


* Communicates with a Control Server via TLS Sockets.


* Polls events from kernel-space via BPF Ring Buffers.




* **Kernel-space (eBPF Programs)**:

**LSM Hooks**: Used for fine-grained access control on files and processes.

**XDP**: Used for high-performance network filtering.
 
**Tracepoints**: Used for monitoring system events like mount/unmount.

## Performance

**Efficiency**: Optimized using eBPF and cache mechanisms, resulting in low CPU overhead (approximately 0.2% to 1.8% during tests).

**Scalability**: Capable of handling an IOC database containing 1 million file hashes and 20,000 IP addresses.

## Technologies Used

* **eBPF / libbpf**: Core technology for safe and efficient kernel-level monitoring.

* **C / C++**: For both eBPF programs and the user-space agent.

* **LMDB**: High-performance key-value store for IOC data.

* **Fanotify**: Linux kernel subsystem for filesystem event monitoring.

## Author

**Khổng Văn Quảng** 
