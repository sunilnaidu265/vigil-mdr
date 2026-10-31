### Playbook: Execution
- PowerShell: -enc/-EncodedCommand, -w hidden, -nop, -ep bypass, IEX, Invoke-Expression, DownloadString, DownloadFile, FromBase64String, Net.WebClient, Invoke-WebRequest, reflection/Assembly.Load. Decode base64 if present and report what it does.
- PowerShell logs: 4104 script block, 4103 module, 400/600 engine start.
- LOLBins: certutil -urlcache/-decode, bitsadmin /transfer, mshta http, rundll32 with odd DLL or javascript:, regsvr32 /i:http (Squiblydoo), msiexec /q http, wmic process call create, InstallUtil, MSBuild, cmstp, forfiles.
- Execution from user-writable paths: AppData, Temp, ProgramData, Users\Public, Downloads, Recycle Bin.
- Unsigned or masquerading binaries (svchost.exe outside System32, misspelled names).
- Execution proof artifacts: Prefetch (run count, last 8 run times), Amcache (SHA1, first run), Shimcache (presence), BAM/DAM, UserAssist, SRUM, Security 4688, Sysmon 1.
