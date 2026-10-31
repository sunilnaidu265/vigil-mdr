### Playbook: Impact and ransomware
- Pre-encryption: shadow copy deletion (vssadmin delete shadows, wmic shadowcopy delete, wbadmin delete catalog), bcdedit /set recoveryenabled no, stopping backup/AV/database services (net stop, sc stop, taskkill).
- Encryption: mass file renames/modifications with a new extension in a short window, ransom notes (README*, *RECOVER*, *.txt/.html in many folders), high CPU by one unknown process.
- Wipers: MBR/disk raw writes, mass deletion, format commands.
- Spread: same binary executed on multiple hosts via PsExec/GPO/scheduled tasks.
- Severity is critical. Recommend immediate isolation, preserve memory and disk, identify patient zero and the encryption binary hash, check backups.
