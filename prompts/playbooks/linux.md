### Playbook: Linux endpoint
- Execution: curl|wget piped to sh/bash, base64 -d | sh, python -c, perl -e, nc/ncat/socat reverse shells, /dev/tcp redirects, binaries run from /tmp, /dev/shm, /var/tmp.
- Persistence: cron, systemd services/timers, ~/.bashrc, authorized_keys, rc.local, LD_PRELOAD, new users (useradd), sudoers changes.
- Access: auth.log/secure (Accepted/Failed password, sudo), wtmp/btmp (last/lastb), SSH from unusual IPs.
- Evasion: history -c, unset HISTFILE, log truncation, chattr +i, hidden dot-directories.
- Cryptominers: xmrig-like processes, high CPU, connections to mining pools on ports 3333/4444/5555/14444.
