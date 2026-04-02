# vt2misp
Script to fetch data from VirusTotal based on a hash (MD5, SHA-1 or SHA-256) and add two objects to a MISP event:
 - File object
 - VirusTotal object

Afterwards it will create a relation between those two (file -> analysed-with -> virustotal-report)


## Requirements

- Python 3.6+
- Install dependencies: `pip install -r requirements.txt`

The script uses the **VirusTotal API v3**.
Sign up at https://www.virustotal.com/#/join-us and find your API key under your profile settings.

## Configuration

Create the file `keys.py` in the same directory:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

misp_url = 'https://misp_instance/'
misp_key = ''  # The MISP auth key can be found on the MISP web interface under the automation section
misp_verifycert = True

proxies = {
    "http" : '',
    "https": ''
}

vt_key = 'API KEY'
vt_delay = 15 # delay in seconds between VirusTotal API calls to avoid hitting the rate limit
```

## Usage

```
usage: vt2misp.py [-h] (-c CHECKSUM | -i FILE) -u UUID [-a COMMENT] [-f] [-v]

options:
  -c, --checksum    MD5, SHA-1 or SHA-256 hash to look up on VT
  -i, --import-file CSV file for batch import (see below)
  -u, --uuid        UUID of the target MISP event (required)
  -a, --comment     Comment to add to the file object (used with -c)
  -f, --force       Add the hash to MISP even if not found on VirusTotal
  -v, --verbose     Include full per-engine detection list in the VT object
```

## Single hash

```
~# python3 vt2misp.py -u 5b53275a-003c-4dcc-b4ce-710f9f590eb0 -a "Phishing attachment" -c 381e0e12e67a5c026529129a264844e7f1029114365ef3be465b72a3bec572c9
Virustotal to MISP
https://www.ecrimelabs.com
----------------------------------------

- Checking if checksum is valid - true
- Checking if UUID format is valid - true
- UUID for MISP event detected
- Checksum 381e0e...c9 was not detected in the event
- The artefact was found on Virustotal
- Creating object(s)
* Permalink: https://www.virustotal.com/gui/file/381e0e12e67a5c026529129a264844e7f1029114365ef3be465b72a3bec572c9
* Detection: 28/62
* Last scan: 2026-04-02 11:55:32

* MD5: 242ba63a35e9647ca61c98081540460b
* SHA1: 5d3f557ad0a0fa661cb5ce04e59b9ad5b917494f
* SHA256: 381e0e12e67a5c026529129a264844e7f1029114365ef3be465b72a3bec572c9
------------
- The MISP objects seems to have been added correctly to the event....
```

## Batch import (CSV)

Use `-i` / `--import-file` to process multiple hashes in one run.

**Format:** `hash,comment` � one entry per line. The comment column is optional. Lines starting with `#` are skipped.

```
# hash,comment
44d88612fea8a8f36de82e1278abb02f,EICAR test file - MD5
3395856ce81f2b7382dee72602f798b642f14d0,EICAR test file - SHA1
275a021bbfb6489e54d471899f7db9d1663fc695b2628214ff1bfbe1a0a3bbdd,EICAR test file - SHA256
242ba63a35e9647ca61c98081540460b,Suspicious file from phishing mail
5d3f557ad0a0fa661cb5ce04e59b9ad5b917494f,Dropped by loader
```

See `example_import.csv` for a ready-to-use template.

```
~# python3 vt2misp.py -u 5b53275a-003c-4dcc-b4ce-710f9f590eb0 -i example_import.csv -v -f
```

Batch behaviour:
- Hashes already present on the event are automatically skipped.
- Default 15-second delay is applied between entries to respect the VT API rate limit.
- Rows with an invalid hash format are skipped with a warning; the rest of the batch continues.
- Hashes not found on VT are skipped unless `-f` is used.

## Force mode

Use `-f` / `--force` to add a hash to MISP even when it is not found on VirusTotal. This creates a file object with only the hash populated, making it easy to enrich later once the file appears on VT.
