### Playbook: Credential access
- LSASS access/dump: Sysmon 10 targeting lsass.exe with high access rights, procdump -ma lsass, rundll32 comsvcs.dll MiniDump, Task Manager dump, *.dmp files written.
- Mimikatz indicators: sekurlsa, lsadump, kerberos::, privilege::debug in command lines or script blocks.
- Registry hive theft: reg save HKLM\SAM / SYSTEM / SECURITY, ntdsutil, vssadmin + copy of NTDS.dit.
- Kerberoasting / AS-REP roasting: many 4769 with RC4 (0x17) for service accounts, 4768 without pre-auth.
- Brute force / spraying: many 4625 then a 4624, same source many accounts.
- Browser credential and cookie theft: access to Login Data, Cookies, Local State by non-browser processes (AiTM/cookie theft).
- Linux: /etc/shadow reads, SSH key theft, credential files in home dirs.
- Impact note: list every account whose credentials may be exposed -> reset.
