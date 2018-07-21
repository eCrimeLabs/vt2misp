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
python3 vt2misp.py -c 7657fcb7d772448a6d8504e4b20168b8 -u 5b51eadd-7e9c-4015-b49c-3df79f590eb0
```

The tool will exit without adding anything to MISP in case the checksum(MD5,
SHA1, SHA256) was not found on VirusTotal. In some cases you might still
want the value you have added to MISP then use the option -f or --force 

This allows you to easilier add additional informaiton should you get it
later and it will then allready be in object format.