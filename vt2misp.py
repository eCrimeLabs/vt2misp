#!/usr/bin/python3
"""
 Fetches data from VT based on a single MD5, SHA1 or SHA256
 and adds the data into two MISP objects on a defined event
 - File object
 - VirusTotal object

Afterwards it will create a Relation between those two (file -> analysed-with -> virustotal-report)

MIT License

Copyright (c) 2018 Dennis Rand (https://www.ecrimelabs.com)

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
import requests
import argparse
import string
import json
import pymisp
from pymisp import MISPObject
from pymisp import PyMISP
from pymisp import MISPEvent
from keys import misp_url, misp_key, proxies, misp_verifycert, vt_url, vt_key

def splash():
    print ('Virustotal to MISP')
    print ('(c)2018 eCrimeLabs')
    print ('https://www.ecrimelabs.com')
    print ("----------------------------------------\r\n")

def init(misp_url, misp_key):
    return PyMISP(misp_url, misp_key, misp_verifycert, 'json', debug=False, proxies=proxies)

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
        misp.update(event)
    except (KeyError, RuntimeError, TypeError, NameError):
        print ("An error occoured when updating the event")
        sys.exit()

    print ("- The MISP objects seems to have been added correctly to the event.... \r\n\r\n")

def vt_query(resource_value, forced):
    params = {'apikey': vt_key, 'resource': resource_value}
    headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
    }
    response = requests.get(vt_url,
      params=params, headers=headers, proxies=proxies)
    json_response = response.json()
    if(json_response['response_code'] == 1):
        print ("- The artefact was found on Virustotal")
        return(json_response)
    else:
        if(forced):
            print ("- The artefact was NOT found on VirusTotal - Continues due to foce mode")
        else:
            print ("Quitting -> The artifact was currently not present on VT")
            sys.exit()


def is_in_misp_event(misp_event):
    found = False
    for obj_loop in misp_event['Object']:
        for attr_loop in obj_loop['Attribute']:
            if(attr_loop['value'] == args.checksum):
                found = True
    return(found)

if __name__ == '__main__':
    splash()
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--checksum", help="The checksum value has to be MD5, SHA-1 or SHA-256 for checking on VT")
    parser.add_argument("-u", "--uuid", help="The UUID of the event in MISP")
    parser.add_argument("-a", "--comment", help="Add comment to the file object, remember to enclose string in \"\" or ''")
    parser.add_argument("-f", "--force", help="Even if the hash is not found on VirusTotal still create the hash given as a file object", action='store_true')
    parser.add_argument("-v", "--verbose", help="Add verbose detection information from VT", action='store_true')
    if len(sys.argv)==1:
    	parser.print_help(sys.stderr)
    	sys.exit(1)
    args = parser.parse_args()

    if (args.comment):
        comments = args.comment
    else:
        comments = ""

    if re.fullmatch("(([a-fA-F0-9]{64})|([a-fA-F0-9]{40})|([a-fA-F0-9]{32}))", args.checksum, re.VERBOSE | re.MULTILINE):
        print ("- Checking if checksum is valid - true")
    else:
    	# Match attempt failed
        print ("Quitting -> No Checksum detected - values has to be md5, sha1 or sha256")
        sys.exit()
    if re.fullmatch(r"([a-fA-F0-9\-]{36})", args.uuid, re.VERBOSE | re.MULTILINE):
        # 5b51eadd-7e9c-4015-b49c-3df79f590eb0
        print ("- Checking if UUID format is valid - true")
    else:
    	# Match attempt failed
        print ("Quitting -> The UUID format is not valid")
        sys.exit()
    misp = init(misp_url, misp_key)
    misp_event = misp.get_event(args.uuid)['Event']

    # Check if Event with that UUID exists in the MISP instance
    try:
        misp_id = misp_event['id']
    except (KeyError, RuntimeError, TypeError, NameError):
        print ("Quitting -> The MISP UUID you entered does not exists on the MISP instance.")
        sys.exit()
    print ('- UUID for MISP event detected')

    # Check if the hash is allready present as an attribut on the event.
    if (is_in_misp_event(misp_event)):
        print ('Quitting -> Checksum ' + args.checksum + ' allready exists on event')
        sys.exit()
    else:
        print ('- Checksum ' + args.checksum + ' was not detected in the event')

    # Query VT API
    vt_data = vt_query(args.checksum, args.force)

    # If in force mode and nothing is returned, we add the checksum value to the correct object
    if not (vt_data):
        vt_data = {}
        vt_data['response_code'] = 0
        if (len(args.checksum) == 32):
            vt_data['md5'] = args.checksum
        elif (len(args.checksum) == 40):
            vt_data['sha1'] = args.checksum
        elif (len(args.checksum) == 64):
            vt_data['sha256'] = args.checksum
        else:
            print ("An error occoured in forced mode, while checking length of checksum")
            sys.exit()

    # Create the objects in the event
    create_objects(vt_data, misp_event, comments, args.force)
