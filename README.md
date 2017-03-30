
*This document is [second project](https://cybersecuritybase.github.io/project2/) of MOOC cyber-security-base course*

# Is it easier to fix the application than to detect attacks?**

The project is to attack system including known vulnerabilities and analyse whether those attack can be detected by Intrusion Detection system. 
First used environment is introduced, then detected and non-detected vulnerabilities are introduced and finally actual question is to be answered.

## Environment
```env
Virtual box
Host only network between VMs

Target VMs:
Win2008 - metasploit3 - firewall disabled
Snort 2.9.9.0-WIN32 - community rules
	snort.exe -i 1 -c c:\Snort\etc\snort.conf -A console
	
Attacks from VM:
Ubuntu 12.05
Metasploit - community edition
```
### Snort configs
The following configs and rules where used in Snort for this exercise.
[Snort configs](/snortconfigs)

## Four attacks Snort can identify

### IIS - FTP

FTP service is open for public access in target VM. Allows access ones weak password is cracked. Snort can detect FTP access ones such rule is added. Community rules did not detect that vulnerability by default
because of course FTP can be intentionally open as well. 

```log
03/21-02:32:54.282748  [**] [1:1000004:0] Testing FTP/TCP alert [**] [Priority: 0] {TCP} 172.28.128.4:34285 -> 172.28.128.3:21
```

### psexec

This vulnerability allows attacker to run remote code with psexec in target system ones weak passwords are cracked. Snort with community rules can detect this attack. 

```log
03/21-02:44:50.593588  [**] [1:1390:15] INDICATOR-SHELLCODE x86 inc ebx NOOP [**] [Classification: Executable code was detected] [Priority: 1] {TCP} 172.28.128.4:1024 -> 172.28.128.3:49221
```

### WinRM
This vulnerability allows attacker to run remote code with WinRM in target system ones weak passwords are cracked. Snort with community rules can detect this attack. 

```log
exploits/windows/winrm/winrm_script_exec
03/21-04:00:20.119249  [**] [1:1390:15] INDICATOR-SHELLCODE x86 inc ebx NOOP [**] [Classification: Executable code was detected] [Priority: 1] {TCP} 172.28.128.4:1024 -> 172.28.128.3:49223
```

### SSH

SSH service is open for public access in target VM.  Allows access ones weak password is cracked. Snort with community rules can detect this unwanted access.

```log
03/21-04:12:35.203256  [**] [1:1325:14] INDICATOR-SHELLCODE ssh CRC32 overflow filler [**] [Classification: Executable code was detected] [Priority: 1] {TCP} 172.28.128.4:50541 -> 172.28.128.3:22
03/21-04:12:39.048800  [**] [129:12:1] Consecutive TCP small segments exceeding threshold [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 172.28.128.4:50541 -> 172.28.128.3:22
03/21-04:12:42.693703  [**] [129:12:1] Consecutive TCP small segments exceeding threshold [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 172.28.128.4:50541 -> 172.28.128.3:22
```

## Two attacks Snort cannot identify

(Remove Snort rules in case otherwise not possible)

### IIS - HTTP [CVE-2015-1635]
Metasploit module: auxiliary/dos/http/ms15_034_ulonglongadd

This vulnerability actually crashes target system so Snort cannot even detect this one. Snort log did not include any information so crash happens before Snort can detect it.
The actual reason for crash is out of the scope this project so it is not checked further. 

### Tomcat [CVE-2009-3843]
Metasploit module:  exploits/multi/http/tomcat_mgr_upload

This vulnerability executes payload in Apache Web Servers. Snort with community rules gives priority 2 warning. Actually there are quite much this type of warnings when running
different attacks but warning itself does not indicate any exploit. So it easily ends up not to trigger any actions.

```log
[**] [129:12:1] Consecutive TCP small segments exceeding threshold [**] [Classification: Potentially Bad Traffic] [Priority: 2] 03/21-02:09:34.957361 172.28.128.4:1024 -> 172.28.128.3:49210 
```

## Summary
The question in this project was whether it would be easier to fix application than detect attacks and my honest answer and believe is **yes**, it has to be easier to fix application than keep Intrusion Detection System and others in such a shape that application would not have to be fixed. Applications shall be fixed and updated when new vulnerabilities have been detected and identified. Of course application can always have zero day vulnerabilities which needs to be tackled by proper software development processes including threat modeling and different testing phases. 

After this project I really feel that detection of different vulnerabilities is hard and most probably cannot be perfect. The required set of rules and fingerprints will eventually come so complex that mainatainability of Intrusion Detection System becomes harder and harder. Then the question will be whether it can be fully trusted anymore, is everything covered, have we breaked something? So having said that it obvioysly means that there needs to be continuous testing also against intrusion detection, not only against application. It anayway will be really hard to be sure that everything is ok and correct actions are always performed. 

I used only community rules and most probably pro rules would have better detection rate. Still in my exercise I was forced to set one new rule and I got only warnings for certain attacks, not proper alarms. My opinion is that best would be to have to have Intrusion Detection system with set of appropriate rules in place. Then vulnerability lists (CVEs) shall be followed and rules shall be updated accordingly. But that's not all, also applications **shall be fixed** to cover cases where Intrusion Detection is not able to detect something due the miss configuration or unproper maintenance.

Below status screen of my metasploit GUI after these attacks + other exploration :smile:

![metasploit status](/metasploit_status.png)

