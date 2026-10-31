### Playbook: Command and control and exfiltration
- Outbound connections from scripting engines, LOLBins, Office, or binaries in user paths.
- Beaconing: repeated connections to the same IP/domain at regular intervals; long-lived connections; rare or newly seen domains; direct-to-IP HTTP(S); unusual ports.
- DNS anomalies: long or random subdomains (tunneling), many TXT queries, Sysmon 22.
- Remote access tools: AnyDesk, ScreenConnect, TeamViewer, Atera, NetSupport, Splashtop, ngrok, cloudflared - installed or run without IT context (RMM abuse).
- Exfiltration: archiving before transfer (7z/rar/zip with passwords, makecab), rclone, megacmd, curl/Invoke-WebRequest POST, uploads to cloud storage or file-sharing, large outbound byte counts (SRUM network usage).
- Report destination (masked), protocol/port, process responsible, and data volume if known.
