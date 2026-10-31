### Playbook: Discovery and lateral movement
- Discovery burst: whoami /all, net user/group/localgroup, net view, nltest /dclist, ipconfig /all, systeminfo, quser, arp -a, AdFind, BloodHound/SharpHound, port scans.
- Lateral movement: PsExec (PSEXESVC service, 7045), sc \\host, WMI (wmiprvse spawning cmd), WinRM (wsmprovhost), RDP (4624 type 10, TerminalServices 1149/21/24/25), SMB admin shares (C$, ADMIN$, 5140/5145), scheduled tasks on remote hosts.
- Logon types: 3 network, 10 remote interactive, 9 NewCredentials (runas /netonly, pass-the-hash), explicit credentials 4648.
- Pass-the-hash/ticket: 4624 type 3 with NTLM from unusual hosts, 4768/4769 anomalies.
- Linux: ssh to internal hosts (auth.log Accepted), scp/rsync, internal scanning.
- Always list source host, destination host, account and method for each hop.
