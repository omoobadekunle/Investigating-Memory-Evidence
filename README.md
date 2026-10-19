# SBT-DF204 – Computer Forensics Case Study 3

## Investigating Memory Evidence: Suspected Illegal File Transfer

![Course](https://img.shields.io/badge/Course-SBT--DF204-blue)
![Tool](https://img.shields.io/badge/Tool-Volatility%202.6.1-orange)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

| Field | Details |
| --- | --- |
| **Student Name** | Adekunle Ogunyemi |
| **Course** | SBT-DF204 – Computer Forensics Case Studies |
| **Assessment** | Case Study 3 – Individual Memory Forensics Investigation |
| **Case Title** | Investigating Suspected Illegal File Transfer From Memory Evidence |
| **Operating System** | Kali Linux |
| **Forensic Tool** | Volatility 2.6.1 |
| **Evidence File** | `memdumpWin7.mem` |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Case Background](#2-case-background)
3. [Objectives of the Investigation](#3-objectives-of-the-investigation)
   - [Forensic Environment](#forensic-environment)
4. [Evidence Acquisition and Integrity](#4-evidence-acquisition-and-integrity)
5. [Volatility Analysis](#5-volatility-analysis)
6. [Timeline of Relevant Activity](#6-timeline-of-relevant-activity)
7. [Evidence Log](#7-evidence-log)
8. [Attribution Assessment](#8-attribution-assessment)
9. [Limitations of the Investigation](#9-limitations-of-the-investigation)
10. [Conclusion](#10-conclusion)
11. [Recommendation](#11-recommendation)
12. [Final Statement](#12-final-statement)
13. [Author](#author)

---

## 1. Executive Summary

This case study involved the investigation of a Windows 7 memory image to determine whether a confidential document was transferred without authorisation. The purpose of the investigation was to examine the supplied memory dump and determine whether the available evidence supported the suspected unauthorised transfer of a file named `secret_file.docx`.

The investigation was carried out using Kali Linux and Volatility 2.6.1. The supplied `memdumpWin7.mem` file was first checked and preserved before analysis. A working copy was created so that the original evidence would not be used directly during the investigation.

The memory analysis showed that the active user profile was **IEUser**. The most important finding came from the command history and console output plugins. The memory contained evidence that the user ran the command `copy secret_file.docx F:` from the Downloads folder, and the console output confirmed that the operation was successful with the message "1 file(s) copied."

Further registry analysis of the `MountedDevices` key proved that the F: drive was a physical USB Mass Storage Device (USB flash drive). File Explorer history (ShellBags) confirmed that the user had browsed the Downloads folder and the F: drive.

Based on the evidence examined, the memory image strongly connects the IEUser account to the unauthorised copy of `secret_file.docx` to a USB device. However, the evidence does not prove with absolute certainty that a specific physical person was operating the computer at that exact time, as user accounts can be shared or left logged in.

---

## 2. Case Background

Investigators obtained a Windows 7 memory image from a workstation after a confidential document may have been transferred without authorization. The inquiry focuses on whether browser activity, a command prompt, a removable device, and a user profile form a defensible sequence of events.

The main purpose of this investigation was therefore to examine the memory image and determine:

- What operating system profile and image time are supported.
- What process and network evidence relates to the transfer.
- What the command history shows.
- What removable-media evidence is present.
- What File Explorer evidence supports the sequence.
- What conclusion can be defended from the available evidence.

---

## 3. Objectives of the Investigation

The objectives of this investigation were:

- To preserve the supplied memory image and verify its integrity.
- To identify the correct Volatility profile.
- To identify relevant processes and network connections.
- To recover the command prompt history and console output.
- To identify the drive letter and device type of the destination drive.
- To examine File Explorer traces that could support the sequence.
- To establish a timeline of the relevant activity in UTC.
- To provide a conclusion based only on the evidence available in the memory image.

### Forensic Environment

The investigation was performed using the following environment:

| Item | Details |
| --- | --- |
| Operating System | Kali Linux |
| Main forensic tool | Volatility 2.6.1 |
| Evidence format | Raw Memory Image (`.mem`) |
| Evidence file | `memdumpWin7.mem` |
| Working file | `working_memdumpWin7.mem` |
| Main plugin examined | `cmdscan`, `consoles`, `printkey` |
| Main service examined | Windows Command Prompt (`cmd.exe`) |

The analysis was performed on a working copy of the memory image rather than making changes to the original evidence file.

---

## 4. Evidence Acquisition and Integrity

### 4.1 Evidence File

The supplied evidence file was: `memdumpWin7.mem`

The file was stored in the evidence directory:

```text
SBT-DF204-Case_Study_3/evidence/memdumpWin7.mem
```

The Kali Linux terminal showed the file size as 10,736,762,288 bytes.

<img width="1457" height="797" alt="image" src="https://github.com/user-attachments/assets/0171f32e-b2eb-4155-ade6-1877ef749ec9" />

*Figure 1: Evidence file memdumpWin7.mem and its recorded file size*

The screenshot shows the terminal command used to list the evidence file, including the file name and size.

### 4.2 SHA-256 Verification

The SHA-256 value of the evidence file was calculated using:

```bash
sha256sum evidence/memdumpWin7.mem
sha256sum working/working_memdumpWin7.mem
```

The calculated hash was:

```text
500bc1ba8b5ffa8053b6213d7e7aae0c84c18cce541dc53a55887e6e5099495e
```

A working copy was also created and hashed. The SHA-256 value of the original file and the working copy matched.

This shows that the working copy was not changed during the copying process.

<img width="1500" height="310" alt="image" src="https://github.com/user-attachments/assets/7193db78-9105-4e74-9921-59db206f890e" />

*Figure 2: SHA-256 comparison of the original evidence file and the working copy*

### 4.3 Creation of the Working Copy

The working copy was created and verified before analysis. The working copy was then used for all Volatility commands:

```bash
python2 volatility/vol.py -f working/working_memdumpWin7.mem [plugin]
```

<img width="1456" height="782" alt="image" src="https://github.com/user-attachments/assets/c352915f-55c8-47ad-a01a-0e98e157179c" />

*Figure 3: Terminal confirming the Volatility tool is available and ready for analysis*

---

## 5. Volatility Analysis

The investigation was mainly based on command-line, registry, and File Explorer artefacts because the suspected transfer involved the Windows command prompt and a removable drive.

The following Volatility plugins were used during the investigation:

- `imageinfo`
- `cmdscan`
- `consoles`
- `printkey -K "MountedDevices"`
- `shellbags`

### 5.1 Finding 1 – Profile Identification

The first stage of the analysis was to identify the operating system profile supported by the memory image.

The following command was used:

```bash
python2 volatility/vol.py -f working/working_memdumpWin7.mem imageinfo
```

The results suggested the following profiles:

- `Win7SP1x86_23418`
- `Win7SP0x86`
- `Win7SP1x86_24000`
- `Win7SP1x86`

The system time was reported as **2019-01-06 15:09:06 UTC**.

The profile `Win7SP1x86` was tested using the `pslist` plugin. The output was successful, confirming this was the correct profile.

<img width="1432" height="1045" alt="image" src="https://github.com/user-attachments/assets/97e716d5-165e-4874-8df2-53cca3ae2ad9" />

*Figure 4: imageinfo output showing suggested Windows 7 profiles and system time*

### 5.2 Finding 2 – Process and Network Activity

After identifying the profile, I examined the running processes and network connections.

The `netscan` plugin identified a closed network connection from:

**Client IP:** 192.168.56.8 to **Destination IP:** 192.168.56.5:80

The Process ID (PID) for this connection was -1, meaning it could not be linked to a specific running process.

<img width="1235" height="680" alt="image" src="https://github.com/user-attachments/assets/d8e9aed2-a5f3-42a9-93dd-9d9e8ad83d6a" />


*Figure 5: netscan output showing a closed connection to 192.168.56.5 with no associated PID*

### 5.3 Finding 3 – Command History

The `cmdscan` plugin was used to examine the command prompt's command history.

The results showed a command process running under `cmd.exe` (PID 3996) with the following commands:

- Command #0: `ipconfig`
- Command #1: `cd Downloads`
- Command #2: `copy secret_file.docx F:`

<img width="1530" height="778" alt="image" src="https://github.com/user-attachments/assets/e8abe50d-a559-4efb-9dae-bb89c2aa5570" />


*Figure 6: cmdscan output showing the command prompt history, including the copy command*

### 5.4 Finding 4 – Console Output

To get the actual screen output of the command prompt, the `consoles` plugin was used.

The console dump showed the user navigating to `C:\Users\IEUser\Downloads` and then running the copy command. The system returned the message: "1 file(s) copied."

This confirmed that the command was executed successfully.

<img width="1522" height="885" alt="image" src="https://github.com/user-attachments/assets/7a0ecb99-86ee-4ac3-bdde-ec71dc2ca003" />

*Figure 7: console output showing the command prompt screen and the "1 file(s) copied" message*

### 5.5 Finding 5 – Removable Media Evidence

To determine what the F: drive was, the `MountedDevices` registry key was examined.

The output showed:

```text
REG_BINARY \DosDevices\F: : (S)
```

The hex data for this key contained the string:

```text
\??\USBSTOR#Disk&Ven_General&Prod_UDisk...
```

This proved that the F: drive was a physical USB Mass Storage Device (USB flash drive).

<img width="1299" height="787" alt="image" src="https://github.com/user-attachments/assets/fd4da441-c079-48cc-b324-2479c0c8ae0f" />

*Figure 8: printkey output of the MountedDevices registry key showing F: is a USB device*

### 5.6 Finding 6 – File Explorer History

The File Explorer history was examined using the `shellbags` plugin.

The results showed that the user had accessed the Downloads folder at 14:49:40 UTC:

```text
C:\Users\IEUser\Downloads
```

The results also showed an entry for the `F:\` drive, confirming that the drive was opened in Windows Explorer.

<img width="1552" height="898" alt="image" src="https://github.com/user-attachments/assets/cb27bd25-f699-448f-83b8-a95ea98bb184" />

*Figure 9: shellbags output showing the Downloads folder and F: drive in File Explorer history*

---

## 6. Timeline of Relevant Activity

The important activity in the memory image can be arranged in the following order.

| Stage | UTC Timestamp | Evidence ID | Source artefact | Observed fact | Interpretation and limit |
| --- | --- | --- | --- | --- | --- |
| Browser or process evidence | 15:08:32 | E04 | `netscan` | Closed connection to 192.168.56.5:80 | Cannot link to the transfer (PID -1). |
| Download-folder review | 14:49:40 | E06 | `shellbags` | User opened Downloads folder | Shows user was browsing files. |
| Removable-device evidence | 15:02:54 | E05 | `printkey` | F: is a USBSTOR device | Proves the destination was a USB drive. |
| Drive mapping | 15:07:03 | E06 | `shellbags` | `F:\` volume accessed | Confirms user opened the USB drive. |
| Command-history evidence | ~15:06 | E03 | `cmdscan` | `copy secret_file.docx F:` | Direct evidence of the copy command. |
| Supported conclusion | ~15:06 | E03/E04 | `consoles` | "1 file(s) copied" | Proves the transfer was successful. |

The relevant transfer occurred at approximately **15:06 UTC**.

<img width="1520" height="958" alt="image" src="https://github.com/user-attachments/assets/7a0a2b33-4e30-4fe1-bbd5-8e28dfbe8f4e" />

*Figure 10: Terminal showing the exact sequence of Volatility commands used to build the timeline*

---

## 7. Evidence Log

| Evidence ID | Evidence / Plugin | Finding | Why it matters | Screenshot |
| --- | --- | --- | --- | --- |
| E01 | `sha256sum` | Original and working copy have matching hashes | Shows integrity of the working copy | Figure 2 |
| E02 | `imageinfo` | Win7SP1x86 profile, 15:09:06 UTC | Establishes the correct profile and image time | Figure 4 |
| E03 | `cmdscan` | `copy secret_file.docx F:` | Directly connects the user to the copy command | Figure 6 |
| E04 | `consoles` | "1 file(s) copied" | Proves the copy operation was successful | Figure 7 |
| E05 | `printkey` | `\DosDevices\F:` is a USBSTOR device | Identifies the destination as a USB drive | Figure 8 |
| E06 | `shellbags` | Downloads folder and F: drive accessed | Corroborates the sequence of activity | Figure 9 |
| E07 | `netscan` | Closed connection to 192.168.56.5 (PID -1) | Shows network activity but cannot link it | Figure 5 |

---

## 8. Attribution Assessment

The evidence can be divided into three levels.

### 8.1 Direct Evidence

The direct evidence shows that:

- The active user account was IEUser.
- The user ran `ipconfig`.
- The user ran `cd Downloads`.
- The user ran `copy secret_file.docx F:`.
- The console confirmed, "1 file(s) copied."
- The F: drive was a USB Mass Storage Device.

### 8.2 Reasonable Inference

From the evidence, it is reasonable to conclude that the IEUser account was used to copy `secret_file.docx` to a USB drive.

The ShellBags history supports this by showing that the Downloads folder and the F: drive were browsed through Windows Explorer.

### 8.3 What the Evidence Does Not Prove

The evidence does not prove with absolute certainty that a specific physical person was sitting at the computer and typing the commands at the exact moment they were run.

The IEUser account could have been shared, or left logged in while another person used the computer.

For this reason, the report should not state that the evidence alone proves the identity of the person who performed the transfer.

---

## 9. Limitations of the Investigation

### 9.1 Shared User Account

The evidence identifies the IEUser account, not a specific person. This is a significant limitation when making an attribution.

### 9.2 Device Does Not Equal Person

The evidence proves the file was copied to a USB drive. It does not prove who plugged in the USB drive or who removed it afterwards.

### 9.3 Network Anomaly

The `netscan` output showed a closed connection to 192.168.56.5. However, because the PID was -1, this connection cannot be linked to the `cmd.exe` process or the file transfer. It must be noted as an alternative explanation that could not be fully investigated.

---

## 10. Conclusion

The investigation of `memdumpWin7.mem` identified an active user account named IEUser. The command history and console output showed that the user navigated to the Downloads folder and ran the command:

```text
copy secret_file.docx F:
```

The console output confirmed the operation was successful with the message "1 file(s) copied."

The `MountedDevices` registry key proved that the F: drive was a physical USB Mass Storage Device. The ShellBags history confirmed that the user had browsed the Downloads folder and the F: drive.

Based on these findings, the evidence strongly supports that the IEUser account was used to copy the confidential file `secret_file.docx` to a USB drive.

However, I would not describe the evidence as absolute proof that a specific person physically operated the computer when the transfer occurred. The shared nature of user accounts and the inability to link the USB device to a specific individual are important limitations.

Overall, the evidence provides a strong connection between the user account, the command prompt activity, and the USB device, but the final attribution should be stated with the limitations described above.

---

## 11. Recommendation

For stronger attribution, additional evidence could be examined if it were available. This could include:

- Windows Event Logs for logon and logoff activity.
- USB device connection and disconnection times.
- Physical access records for the workstation.
- CCTV footage if available.
- Examination of the USB device itself.
- Network logs to investigate the 192.168.56.5 connection.

These additional sources could help establish who was actually using the device at the time of the transfer.

---

## 12. Final Statement

This investigation was carried out using the supplied memory image and Volatility 2.6.1. The original evidence was preserved, a working copy was created, and the hash values were compared before analysis.

The memory image provided enough information to trace the unauthorised copy of `secret_file.docx` to the IEUser account and to prove that the destination was a USB drive.

The evidence therefore provides a strong association between the IEUser account and the USB transfer of the confidential document, while the shared nature of user accounts remains a limitation when making a final statement about the person who physically performed the transfer.

---

## Author

**Adekunle Ogunyemi**  
SBT-DF204 – Computer Forensics Case Studies  
Case Study 3 – Investigating Memory Evidence

---

> **Note:** The memory image (`memdumpWin7.mem`) is not included in this repository because of its size. Its SHA-256 hash is recorded in [Section 4.2](#42-sha-256-verification) so a copy of the image can be verified against it.
