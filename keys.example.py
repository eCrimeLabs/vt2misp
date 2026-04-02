#!/usr/bin/env python3
# -*- coding: utf-8 -*-

misp_url = 'https://misp_instance/'
misp_key = '' # The MISP auth key can be found on the MISP web interface under the automation section
misp_verifycert = True

proxies = {
    "http" : '127.0.0.1:8090',
    "https": '127.0.0.1:8090'
}

vt_key = 'API KEY'
vt_delay = 15 # delay in seconds between VirusTotal API calls to avoid hitting the rate limit