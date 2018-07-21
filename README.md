# vt2misp
Script to fetch data from virustotal and add two specific objects to an event.
 - File object
 - VirusTotal object

Afterwards it will create a Relation between those two (file -> analysed-with -> virustotal-report)

The script makes use of the public VirusTotal API
In order to use the API you must sign up to VirusTotal Community(https://www.virustotal.com/#/join-us).
Once you have a valid VirusTotal Community account you will find your personal API key in your personal settings section.
This key is all you need to use the VirusTotal API.

Remember to create the file "keys.py":
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-

misp_url = 'https://misp_instance/'
misp_key = '' # The MISP auth key can be found on the MISP web interface under the automation section
misp_verifycert = True

vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'
vt_key = 'API KEY'
```

Sample Usage:
```
~# python3 vt2misp.py -u 5b53275a-003c-4dcc-b4ce-710f9f590eb0 -a "USBGuard" --force -c 7657fcb7d772448a6d8504e4b20168b8
Virustotal to MISP
(c)2018 eCrimeLabs
https://www.ecrimelabs.com
----------------------------------------

- Checking if checksum is valid - true
- Checking if UUID format is valid - true
- UUID for MISP event detected
- Checksum 7657fcb7d772448a6d8504e4b20168b8 was not detected in the event
- The artefact was found on Virustotal
- Creating object(s)
	* Permalink: https://www.virustotal.com/file/54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71/analysis/1532138638/
	* Detection: 64/67
	* Last scan: 2018-07-21 02:03:58

	* MD5: 7657fcb7d772448a6d8504e4b20168b8
	* SHA1: 84c7201f7e59cb416280fd69a2e7f2e349ec8242
	* SHA256: 54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71
	------------
	* VirusTotal detections: 
		Bkav (1.3.0.9466) Detection: W32.ZeustrackerZS.Trojan
		MicroWorld-eScan (14.0.297.0) Detection: Gen:Variant.Kazy.8782
		CMC (1.1.0.977) Detection: Trojan.Win32.Lebag!O
		CAT-QuickHeal (14.00) Detection: Trojan.Ramnit.A
		McAfee (6.0.6.653) Detection: PWS-Zbot.gen.cy
		Malwarebytes (2.1.1.1115) Detection: Trojan.Zbot
		Zillya (2.0.0.3599) Detection: Trojan.Zbot.Win32.81569
		SUPERAntiSpyware (5.6.0.1032) Detection: Trojan.Agent/Gen-FakeSecurity
		TheHacker (6.8.0.5.3418) Detection: Trojan/Lebag.agu
		K7GW (10.54.27826) Detection: Riskware ( 0015e4f11 )
		K7AntiVirus (10.54.27825) Detection: Riskware ( 0015e4f11 )
		Invincea (6.3.5.26121) Detection: heuristic
		Baidu (1.0.0.2) Detection: Win32.Worm.Autorun.f
		Babable (9107201) Detection: No detection
		F-Prot (4.7.1.166) Detection: W32/Ramnit.K.gen!Eldorado
		Symantec (1.6.0.0) Detection: W32.Ramnit
		TotalDefense (37.1.62.1) Detection: Win32/Ramnit.B!Dropper
		TrendMicro-HouseCall (9.950.0.1006) Detection: TSPY_ZBOT.SMHA
		Paloalto (1.0) Detection: generic.ml
		ClamAV (0.100.1.0) Detection: Win.Trojan.Ramnit-7847
		Kaspersky (15.0.1.13) Detection: Worm.Win32.Autorun.icp
		BitDefender (7.2) Detection: Gen:Variant.Kazy.8782
		NANO-Antivirus (1.0.116.23366) Detection: Trojan.Win32.DownLoad2.wtigj
		ViRobot (2014.3.20.0) Detection: Trojan.Win32.Agent.109056.CR
		Avast (18.4.3895.0) Detection: Win32:Kryptik-JOV [Trj]
		Tencent (1.0.0.1) Detection: Worm.Win32.AutoRun.aaa
		Ad-Aware (3.0.5.370) Detection: Gen:Variant.Kazy.8782
		Sophos (4.98.0) Detection: Troj/ZXC-G
		Comodo (29383) Detection: TrojWare.Win32.Kryptik.KLV
		F-Secure (11.0.19100.45) Detection: Gen:Variant.Kazy.8782
		DrWeb (7.0.33.6080) Detection: Win32.HLLW.Tazebama.235
		VIPRE (68268) Detection: Trojan.Win32.Generic!BT
		TrendMicro (10.0.0.1040) Detection: TSPY_ZBOT.SMHA
		McAfee-GW-Edition (v2017.3010) Detection: BehavesLike.Win32.ZBot.ch
		Emsisoft (2018.4.0.1029) Detection: Gen:Variant.Kazy.8782 (B)
		SentinelOne (1.0.17.227) Detection: static engine - malicious
		Cyren (6.0.0.4) Detection: W32/Ramnit.K.gen!Eldorado
		Jiangmin (16.0.100) Detection: Trojan/Generic.dkmt
		Webroot (1.0.0.403) Detection: Trojan:Win32/Eyestye.H
		Avira (8.3.3.6) Detection: TR/Drop.Liks.A
		Fortinet (5.4.247.0) Detection: W32/Kryptik.KLV!tr
		Antiy-AVL (3.0.0.1) Detection: Worm/Win32.Autorun.icp
		Kingsoft (2013.8.14.323) Detection: Win32.Troj.Undef.(kcloud)
		Endgame (3.0.0) Detection: malicious (high confidence)
		Arcabit (1.0.0.831) Detection: Trojan.Kazy.D224E
		AegisLab (4.2) Detection: Worm.Win32.Autorun.o!c
		ZoneAlarm (1.0) Detection: Worm.Win32.Autorun.icp
		Avast-Mobile (180720-04) Detection: No detection
		Microsoft (1.1.15100.1) Detection: Trojan:Win32/Ramnit
		AhnLab-V3 (3.13.1.21452) Detection: Trojan/Win32.Zbot.R19508
		ALYac (1.1.1.5) Detection: Gen:Variant.Kazy.8782
		AVware (1.6.0.52) Detection: Trojan.Win32.Generic!BT
		MAX (2017.11.15.1) Detection: malware (ai score=100)
		VBA32 (3.12.32.0) Detection: Worm.AutoRun
		Cylance (2.3.1.101) Detection: Unsafe
		Zoner (1.0) Detection: Win32.Ramnit.A
		ESET-NOD32 (17750) Detection: Win32/Ramnit.A
		Rising (25.0.0.24) Detection: Trojan.Win32.Generic.127B2A0E (C64:YzY0OklB66P4SAs3)
		Yandex (5.5.1.3) Detection: Trojan.Ramnit!cLbJ7UZPdfE
		Ikarus (0.1.5.2) Detection: Virus.Win32.Virtob
		eGambit (None) Detection: No detection
		GData (A:25.17830B:25.12774) Detection: Gen:Variant.Kazy.8782
		AVG (18.4.3895.0) Detection: Win32:Kryptik-JOV [Trj]
		Cybereason (1.2.27) Detection: malicious.7d7724
		Panda (4.6.4.2) Detection: Trj/Ramnit.F
		CrowdStrike (1.0) Detection: malicious_confidence_100% (W)
		Qihoo-360 (1.0.0.1120) Detection: Win32/Trojan.544
		
	------------
- The MISP objects seems to have been added correctly to the event.... 
```

The tool will exit without adding anything to MISP in case the checksum(MD5, SHA1, SHA256) was not found on VirusTotal. 
In some cases you might still want the value you have added to MISP then use the option -f or --force 

This allows you to easilier add additional informaiton should you get it later and it will then allready be in object format.
