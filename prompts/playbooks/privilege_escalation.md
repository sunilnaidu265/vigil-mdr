### Playbook: Privilege escalation
- Process running as SYSTEM or high integrity spawned from a medium-integrity user process.
- UAC bypass: fodhelper, eventvwr, computerdefaults, sdclt with registry hijack of ms-settings or mscfile.
- Token manipulation, named-pipe impersonation (Potato tools), Print Spooler abuse.
- Vulnerable driver load (BYOVD), Sysmon 6, unusual service creation by a user.
- Special privileges assigned (4672) to unexpected accounts; group changes (4728/4732/4756).
- Linux: sudo abuse (auth.log), SUID binaries, writable cron/systemd, kernel exploit compile and run in /tmp.
