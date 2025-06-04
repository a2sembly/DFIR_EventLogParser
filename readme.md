# 🕵️‍♀️ DFIR EventLog Parser
A tiny, **Python‑powered** toolkit that turns noisy Windows *.evtx* files into neat CSV for Digital Forensics & Incident Response (DFIR) work.  
“Feed me an EVTX, I’ll feed you the **who / what / where / when**!” 🚀  

![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python) ![Platform](https://img.shields.io/badge/OS-Windows%20%7C%20Linux-lightgrey) ![Stars](https://img.shields.io/github/stars/a2sembly/DFIR_EventLogParser?style=social)

---

## ✨ Features
| 💡 What it does | 📂 Target Log & Event IDs | 📑 Output columns (subset) |
|-----------------|--------------------------|---------------------------|
| **RDP Session History** | *Microsoft‑Windows‑TerminalServices‑LocalSessionManager/Operational* → 21, 22, 23, 24, 25, 39, 40 | `Timestamp, Host, PublicIP, SessionID, Action, …` |
| **RDP Client (Outbound) Activity** | *Microsoft‑Windows‑TerminalServices‑RDPClient/Operational* → 1024, 1026 | `Timestamp, RemoteIP, HostApp, Outcome, …` |
| **Interactive / Network Logons** | *Security.evtx* → 4624, 4625, 4634, 4648, 1102, 4720, 4722, 4724, 4723, 4725, 4726, 4781, 4738, 4688, 4732, 4733 | `User, LogonType, IP:Port, Process, …` |
| **PowerShell Command Audit** | *Microsoft‑Windows‑PowerShell/Operational* → 400 | `Command, HostApplication, User, …` |
| **Service Installation** | *System.evtx* → 104, 7036, 7045 | `ServiceName, Path, StartType, …` |
| **WinRM Operations** | *Microsoft‑Windows‑WinRM/Operational* → 132, 145 | `OperationName, ResourceURI, User, …` |


All parsers share the **same CSV header**, so you can concatenate results effortlessly.  
Need more? Just drop a new parser in `PARSERS` inside `main.py`.

---

## 🔧 Installation

```bash
# 1⃣  Get Python ≥ 3.7
# 2⃣  Clone the repo
git clone https://github.com/a2sembly/DFIR_EventLogParser.git
cd DFIR_EventLogParser
```

# 3⃣  Install dependencies
```
pip install python-evtx      # main dependency
```

---

## 🚀 Quick start
### Parse inbound RDP sessions and save as CSV
```
python main.py \
    --type ts_lsm \
    --input "C:\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" \
    --output rdp_sessions.csv
```

### Parse all EVTX in the folder
```
python main.py \
    --type auto \
    --input "C:\Windows\System32\winevt\Logs" \
    --output "C:\Users\user\Desktop"
```




