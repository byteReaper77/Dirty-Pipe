# Dirty Pipe Exploit (CVE-2022-0847)

## Overview

This repository contains a **Proof of Concept (PoC)** exploit for the **Dirty Pipe vulnerability (CVE-2022-0847)**, which affects **Linux kernel versions 5.8 to 5.16**. This vulnerability allows **local privilege escalation** by exploiting improper handling of pipe buffers in the kernel, enabling an attacker to modify read-only files (such as SUID binaries) and execute arbitrary code with elevated privileges.

## Description

The Dirty Pipe vulnerability is a critical issue found in Linux kernel versions between **5.8 and 5.16**. It allows local privilege escalation by exploiting improper handling of pipe buffers in the kernel. This vulnerability can be triggered by writing to a read-only file (such as SUID binaries), which can lead to **arbitrary code execution** and potentially a **root shell** on the affected system.

### Key Features:
- **Privilege Escalation**: Escalates privileges from an unprivileged user to root.
- **Targeted Attack**: Targets read-only files like SUID binaries.
- **Custom ELF Shellcode**: Injects custom shellcode into a target file to spawn a root shell.
- **Anti-Debugging**: Contains anti-debugging mechanisms to avoid detection by reverse engineers.

## Exploit Flow

1. **Kernel Version Check**: Verifies the kernel version to ensure it lies within the vulnerable range (5.8 to 5.16).
2. **Pipe Buffer Manipulation**: The exploit manipulates the pipe buffer flags to trigger the Dirty Pipe vulnerability.
3. **Payload Injection**: A custom ELF shellcode is injected into the target file (e.g., a SUID binary).
4. **Hijack SUID Binary**: The targeted binary is hijacked by overwriting its contents with the injected shellcode.
5. **Execute Hijacked Binary**: The hijacked binary is executed, resulting in the spawning of a root shell.
6. **Restore Original Binary**: The original content of the SUID binary is restored to avoid detection.
7. **Persistent Root Shell**: A root shell is opened with elevated privileges.


### Prerequisites

- A **Linux** system running a vulnerable kernel version (**5.8 to 5.16**).
- A **SUID binary** that can be exploited for privilege escalation.

### Compilation and Running the Exploit

To compile the exploit, run the following command:

gcc dirtypipe.c -Wall -O2 -fno-pie -no-pie -o dirtypipe

Notes:

Ensure that the target SUID binary is exploitable and resides in a path that can be accessed by the user running the exploit.

The system must be running a vulnerable version of the Linux kernel (5.8 to 5.16).

Anti-Debugging Features
The exploit contains an anti-debugging mechanism to prevent detection by debugging tools such as gdb. If the exploit detects the presence of a debugger, it will terminate early, making it more difficult for attackers to analyze the code.

How It Works:
The exploit checks for debugging activity by inspecting /proc/self/status and uses ptrace system calls to detect if the program is being traced by a debugger.

If a debugger is detected, the exploit will stop executing and exit, making reverse engineering harder.

Disclaimer
This exploit is provided for educational and research purposes only. Unauthorized use of this exploit is illegal and unethical. Running this exploit on any system without explicit permission from the system owner is prohibited and could result in legal consequences.

The author is not responsible for any damages, data loss, or legal ramifications resulting from the use or misuse of this exploit.

