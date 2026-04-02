#!/usr/bin/python3
"""
 Fetches data from VT based on a single MD5, SHA1 or SHA256
 and adds the data into two MISP objects on a defined event
 - File object
 - VirusTotal object

Afterwards it will create a Relation between those two (file -> analysed-with -> virustotal-report)

Please ensure that you early 2020 are using Python 3.6+
---
DeprecationWarning: Call to deprecated method __init__.
(Please use ExpandedPyMISP instead (requires Python 3.6+).
This class will be an alias of ExpandedPyMISP early 2020 and your code will most probably fail.
---

Late 2019 this code will convert to requiring Python 3.6+


MIT License

Copyright (c) 2019 Dennis Rand (https://www.ecrimelabs.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import re
import sys
import csv
import time
import requests
import argparse
import string
import json
from datetime import datetime, timezone
import pymisp
from pymisp import MISPObject
from pymisp import PyMISP
from pymisp import MISPEvent
from keys import misp_url, misp_key, proxies, misp_verifycert, vt_key, vt_delay

def splash():
    print ('Virustotal to MISP')
    print ('https://www.ecrimelabs.com')
    print ("----------------------------------------\r\n")

def init(misp_url, misp_key):
    return PyMISP(misp_url, misp_key, misp_verifycert, debug=False, proxies=proxies)

def create_objects(vt_results, event_dict, comments, forced):
    event = MISPEvent()
    event.from_dict(**event_dict)
    vt_data = ''

    print ("- Creating object(s)")
    if (vt_results['response_code'] == 1):
        # Add VT Object
        for obj_loop in vt_results['scans']:
            if (vt_results['scans'][obj_loop]['detected'] == True):
                vt_data += "%s (%s) Detection: %s\r\n"% (obj_loop, vt_results['scans'][obj_loop]['version'], vt_results['scans'][obj_loop]['result'])
            else:
                vt_data += "%s (%s) Detection: No detection\r\n"% (obj_loop, vt_results['scans'][obj_loop]['version'])

        detection = "%s/%s"% (vt_results['positives'],vt_results['total'])
        vt_comment = "File %s"% (vt_results['md5'])
        misp_object = event.add_object(name='virustotal-report', comment=vt_comment, distribution=5, standalone=False)
        obj_attr = misp_object.add_attribute('permalink', value=vt_results['permalink'], distribution=5)
        misp_object.add_attribute('detection-ratio', value=detection, distribution=5)
        if(args.verbose):
            misp_object.add_attribute('comment', value=vt_data, disable_correlation=True, distribution=5)

        misp_object.add_attribute('last-submission', value=vt_results['scan_date'], disable_correlation=True, distribution=5)
        vt_obj_uuid = misp_object.uuid
        print ("\t* Permalink: " + vt_results['permalink'])
        print ("\t* Detection: " + detection)
        print ("\t* Last scan: " + vt_results['scan_date'] + "\r\n")

    # Add File Object
    misp_object = event.add_object(name='file', comment=comments, standalone=False)
    obj_attr = []
    try:
        misp_object.add_attribute('md5', value=vt_results['md5'], distribution=5)
    except KeyError:
        vt_results['md5'] = None

    try:
        misp_object.add_attribute('sha1', value=vt_results['sha1'], distribution=5)
    except KeyError:
        vt_results['sha1'] = None

    try:
        misp_object.add_attribute('sha256', value=vt_results['sha256'], distribution=5)
    except KeyError:
        vt_results['sha256'] = None

    # Adding object to object relation
    if (vt_results['response_code'] == 1):
        misp_object.add_reference(referenced_uuid=vt_obj_uuid, relationship_type='analysed-with', comment='Expanded with virustotal data')

    if not (vt_results['md5'] == None):
        print ("\t* MD5: " + vt_results['md5'])

    if not (vt_results['sha1'] == None):
        print ("\t* SHA1: " + vt_results['sha1'])

    if not (vt_results['sha256'] == None):
        print ("\t* SHA256: " + vt_results['sha256'])

    if (vt_results['response_code'] == 1):
        print ("\t------------")
        print ("\t* VirusTotal detections: ")
        vt_detects = vt_data.split('\n')
        for vt_detect in vt_detects:
            print ("\t\t" + vt_detect)
        print ("\t------------")

    try:
        # Submit the File and VT Objects to MISP
        misp.update_event(event)
    except (KeyError, RuntimeError, TypeError, NameError):
        print ("An error occoured when updating the event")
        sys.exit()

    print ("- The MISP objects seems to have been added correctly to the event.... \r\n\r\n")

def vt_query(resource_value, forced):
    url = f'https://www.virustotal.com/api/v3/files/{resource_value}'
    headers = {
      "x-apikey": vt_key,
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
    }
    response = requests.get(url, headers=headers, proxies=proxies)
    if response.status_code == 200:
        attrs = response.json()['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        positives = stats.get('malicious', 0)
        excluded = {'type-unsupported', 'timeout', 'confirmed-timeout', 'failure'}
        total = sum(v for k, v in stats.items() if k not in excluded)
        sha256 = attrs.get('sha256', resource_value)
        scan_ts = attrs.get('last_analysis_date', 0)
        scan_date = datetime.fromtimestamp(scan_ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        scans = {}
        for av, details in attrs.get('last_analysis_results', {}).items():
            scans[av] = {
                'detected': details.get('category') == 'malicious',
                'version': details.get('engine_version') or '',
                'result': details.get('result') or '',
            }
        result = {
            'response_code': 1,
            'md5': attrs.get('md5'),
            'sha1': attrs.get('sha1'),
            'sha256': sha256,
            'positives': positives,
            'total': total,
            'permalink': f'https://www.virustotal.com/gui/file/{sha256}',
            'scan_date': scan_date,
            'scans': scans,
        }
        print ("- The artefact was found on Virustotal")
        return result
    elif response.status_code == 404:
        if(forced):
            print ("- The artefact was NOT found on VirusTotal - Continues due to force mode")
            return None
        else:
            print ("\r\n- The artifact was currently not present on VT - Skipping")
            return None
    else:
        print (f"\r\n- VT API returned HTTP {response.status_code} - Skipping")
        return None


def is_in_misp_event(misp_event, checksum):
    found = False
    for obj_loop in misp_event['Object']:
        for attr_loop in obj_loop['Attribute']:
            if(attr_loop['value'] == checksum):
                found = True
    return(found)

CHECKSUM_RE = re.compile(r'^([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})$')

if __name__ == '__main__':
    splash()
    parser = argparse.ArgumentParser()
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-c", "--checksum", help="MD5, SHA-1 or SHA-256 hash to check on VT")
    input_group.add_argument("-i", "--import-file", dest="import_file", metavar="FILE",
                             help="CSV file with columns: hash[,comment] — one entry per line")
    parser.add_argument("-u", "--uuid", help="The UUID of the event in MISP", required=True)
    parser.add_argument("-a", "--comment", help="Add comment to the file object (used with -c)", default="")
    parser.add_argument("-f", "--force", help="Even if the hash is not found on VirusTotal still create the hash given as a file object", action='store_true')
    parser.add_argument("-v", "--verbose", help="Add verbose detection information from VT", action='store_true')
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()

    if re.fullmatch(r'[a-fA-F0-9\-]{36}', args.uuid):
        print ("- Checking if UUID format is valid - true")
    else:
        print ("\r\n- Quitting -> The UUID format is not valid")
        sys.exit()

    misp = init(misp_url, misp_key)
    misp_event = misp.get_event(args.uuid)['Event']

    # Check if Event with that UUID exists in the MISP instance
    try:
        misp_id = misp_event['id']
    except (KeyError, RuntimeError, TypeError, NameError):
        print ("\r\n- Quitting -> The MISP UUID you entered does not exists on the MISP instance.")
        sys.exit()
    print ('- UUID for MISP event detected')

    # Build list of (checksum, comment) entries to process
    if args.import_file:
        entries = []
        try:
            with open(args.import_file, newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    if not row or row[0].strip().startswith('#'):
                        continue
                    hash_val = row[0].strip()
                    comment_val = row[1].strip() if len(row) > 1 else ""
                    if not CHECKSUM_RE.match(hash_val):
                        print (f"- Skipping invalid checksum: {hash_val}")
                        continue
                    entries.append((hash_val, comment_val))
        except FileNotFoundError:
            print (f"\r\n- Quitting -> Import file not found: {args.import_file}")
            sys.exit()
        print (f"- Loaded {len(entries)} entries from {args.import_file}")
    else:
        if not CHECKSUM_RE.match(args.checksum):
            print ("\r\n- Quitting -> No Checksum detected - values has to be MD5, SHA1 or SHA256")
            sys.exit()
        print ("- Checking if checksum is valid - true")
        entries = [(args.checksum, args.comment)]

    processed = set()
    for checksum, comments in entries:
        print (f"\r\n- Processing: {checksum}")
        if checksum in processed:
            print ('- Skipping -> Checksum ' + checksum + ' already processed in this run')
            continue
        if is_in_misp_event(misp_event, checksum):
            print ('- Skipping -> Checksum ' + checksum + ' already exists on event')
            continue
        print ('- Checksum ' + checksum + ' was not detected in the event')

        # Query VT API
        vt_data = vt_query(checksum, args.force)

        # If in force mode and nothing is returned, build a minimal result from the checksum
        if not vt_data:
            if not args.force:
                processed.add(checksum)
                continue
            vt_data = {'response_code': 0}
            if len(checksum) == 32:
                vt_data['md5'] = checksum
            elif len(checksum) == 40:
                vt_data['sha1'] = checksum
            elif len(checksum) == 64:
                vt_data['sha256'] = checksum
            else:
                print ("An error occoured in forced mode, while checking length of checksum")
                continue

        create_objects(vt_data, misp_event, comments, args.force)
        processed.add(checksum)

        # Refresh local copy of the event so the next iteration sees up-to-date objects
        misp_event = misp.get_event(args.uuid)['Event']

        if len(entries) > 1:
            print (f"- Waiting {vt_delay} seconds before next VT lookup...")
            time.sleep(vt_delay)
