# vt2misp
Script to fetch data from virustotal and add it to a specific event as an object

Remember to create "keys.py":
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-

misp_url = 'https://misp instance/'
misp_key = '' # The MISP auth key can be found on the MISP web interface under the automation section
misp_verifycert = True

vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'
vt_key = 'API KEY'
```
