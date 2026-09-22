# Kernel-Level Ransomware Protection & Recovery (Ring 0)
A kernel-mode mechanism to detect, block, and recover data from ransomware attacks using file system mini-filters.

## 📌 Overview
This project explores a kernel-mode defense mechanism against Ransomware. By utilizing hooking/mini-filter techniques at Ring 0, the system monitors I/O system calls, detects unauthorized mass encryption behavior, blocks the malicious process, and recovers affected data.

## 🛠️ Architecture & Core Components
*   **GuardianDriver.sys:** A Windows Kernel Driver designed to intercept file system operations (I/O Requests).
*   **GuardianService.exe:** The user-mode service communicating with the kernel driver to enforce quarantine rules.
*   **PowerShell Automation:** Automated deployment scripts for driver installation, teardown, and attack simulation (Canary files).

## 🚀 Key Features
*   **Ring 0 I/O Interception:** Monitors file modification attempts at the lowest OS level, bypassing user-mode EDR evasion techniques.
*   **Canary File Traps:** Deploys decoy files to act as early warning triggers (`simulate_canary_attack.ps1`).
*   **Process Quarantine & Blocking:** Immediately suspends and isolates processes exhibiting ransomware-like encryption behavior.
*   **Automated Data Recovery:** Mechanisms to restore original files from secure kernel-level buffers before malicious encryption completes.

## 📺 Demonstration
*   **[Video 1: Detection & Quarantine]**(https://youtu.be/Eo_aaJ_50PQhttps://youtu.be/Eo_aaJ_50PQ)
*   **[Video 2: Data Recovery Process]**(https://youtu.be/FiPTK5mev38)

## 📖 Detailed Documentation
For an in-depth analysis of the kernel hooking methodologies and architecture, please review the full project report.
