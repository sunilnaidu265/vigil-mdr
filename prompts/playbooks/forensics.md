### Playbook: Forensic artifact interpretation (deep investigation)
Windows - what each artifact proves:
- Prefetch (C:\Windows\Prefetch\*.pf): program executed, run count, up to 8 last run times, files loaded.
- Amcache.hve: program present/executed, SHA1, path, first-run time.
- Shimcache (AppCompatCache): file existed on the system (not proof of execution on Win10+).
- BAM/DAM, UserAssist: per-user execution with last-run time.
- SRUM: per-app network bytes sent/received and runtime (exfiltration volume).
- MFT/$UsnJrnl/$LogFile: file create/modify/rename/delete times; compare $SI vs $FN for timestomping.
- LNK files and Jump Lists: files/folders opened, original paths, volume serials, remote shares.
- ShellBags: folders browsed, including removable drives and network shares.
- Registry: Run keys, services, USBSTOR (USB devices), MountedDevices, RecentDocs, TypedPaths.
- Event logs: Security 4624/4625/4634/4648/4672/4688/4697/4698/4720/4732/1102; System 7045/104; PowerShell 4103/4104; Sysmon 1,3,7,8,10,11,13,22; TerminalServices 21/24/25/1149; Defender 1116/1117/5001/5007.
- Browser: history, downloads, cookies, cache - initial access and C2 URLs.
Linux - auth.log/secure, syslog/journal, wtmp/btmp/lastlog, bash_history, cron, systemd units, /tmp and /dev/shm contents.
Method:
- Build one super-timeline across artifacts, sorted by UTC time, and state which artifact proves each step.
- Note when a time comes from a less reliable artifact (Shimcache, $SI times).
- Recommend evidence preservation: memory capture first (volatile), then disk image, keep chain of custody, hash all collected files.
