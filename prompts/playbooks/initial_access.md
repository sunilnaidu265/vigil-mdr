### Playbook: Initial access (phishing, drive-by, exposed services)
- Office/PDF/browser/archive tool spawning cmd, powershell, wscript, cscript, mshta, rundll32, regsvr32.
- Files from email or browser downloads (Downloads, Outlook INetCache/Content.Outlook, Temp\7z*, Temp\Rar$*) executed shortly after arrival.
- Mark-of-the-Web (Zone.Identifier ADS) on executed files, ISO/IMG/VHD mounts, LNK files with long arguments, .hta/.js/.vbs/.one attachments.
- Web servers (w3wp, httpd, nginx, java, tomcat) spawning shells = webshell or exploitation.
- External RDP/SSH/VPN logons followed by new processes.
- Artifacts: browser history/downloads, Outlook attachment cache, Zone.Identifier, Sysmon 1/11/15, Security 4624 type 10, IIS/Apache logs.
