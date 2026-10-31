### Playbook: Persistence
- Registry Run/RunOnce (HKCU/HKLM ...\CurrentVersion\Run), Winlogon Userinit/Shell, Image File Execution Options Debugger, AppInit_DLLs, COM hijacks (HKCU\Software\Classes\CLSID).
- Scheduled tasks: schtasks /create, Security 4698/4702, TaskScheduler 106/140/200, task XML in C:\Windows\System32\Tasks.
- Services: sc create / New-Service, System 7045, Security 4697, binaries outside System32.
- WMI event subscriptions (__EventFilter, CommandLineEventConsumer), Sysmon 19/20/21, WMI-Activity 5861.
- Startup folder writes, new local accounts (4720) added to Administrators (4732).
- Linux: cron (/etc/cron*, crontab -e), systemd units (/etc/systemd/system), ~/.bashrc/.profile, authorized_keys, rc.local, LD_PRELOAD.
- Report the exact key/task/service name and the payload path it launches.
