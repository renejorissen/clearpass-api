#!/usr/bin/env python3
#------------------------------------------------------------------------------
#
# Script to list get endpoints with predefined Attribute Source:MobileIron
# Delete the endpoint and poll context server to import endpoints from MobileIron
#
#------------------------------------------------------------------------------

import requests
import json
from configparser import ConfigParser
import os
import urllib3
import pprint
from html import escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# configuration file parameters
params = os.path.join(os.path.dirname(__file__), "../config/params.cfg")
config = ConfigParser()
config.read(params)

clearpass_fqdn = config.get('ClearPass', 'clearpass_fqdn')
oauth_grant_type = config.get('OAuth2', 'grant_type')
oauth_client_id = config.get('OAuth2', 'client_id')
oauth_client_secret = config.get('OAuth2', 'client_secret')
oauth_username = config.get('OAuth2', 'username')
oauth_password = config.get('OAuth2', 'password')


# validate config
def check_config(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret, oauth_username, oauth_password):
    """Validate the OAuth 2.0 configuration from the params.cfg file."""

    if not clearpass_fqdn:
        print('Error: ClearPass FQDN must be defined in config file (config/params.cfg)')
        exit(1)
    if not oauth_grant_type:
        print('Error: grant_type must be defined in config file (config/params.cfg)')
        exit(1)
    if not oauth_client_id:
        print('Error: client_id must be defined in config file (config/params.cfg)')
        exit(1)
    if oauth_grant_type == "password" and (not oauth_username or not oauth_password):
        print('Error: username and password must be defined in config file for password grant type (config/params.cfg)')
        exit(1)


####################################################################
###  AUTHENTICATION TO CLEARPASS
####################################################################

def get_access_token(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret, oauth_username, oauth_password):
    """Get OAuth 2.0 access token with config from params.cfg"""

    url = "https://" + clearpass_fqdn + "/api/oauth"

    headers = {'Content-Type':'application/json'}

    # grant_type: password
    if oauth_grant_type == "password":
        payload = {'grant_type':oauth_grant_type, 'username':oauth_username, 'password':oauth_password, 'client_id':oauth_client_id, 'client_secret':oauth_client_secret}
        #print(payload)
        try:
            r = requests.post(url, headers=headers, json=payload, verify=False, timeout=2)
            r.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        json_response = json.loads(r.text)

        return json_response

    # grant_type: password   public client
    if oauth_grant_type == "password" and not oauth_client_secret:
        payload = {'grant_type':oauth_grant_type, 'username':oauth_username, 'password':oauth_password, 'client_id':oauth_client_id}

        try:
            r = requests.post(url, headers=headers, json=payload, verify=False, timeout=2)
            r.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        json_response = json.loads(r.text)

        return json_response

    # grant_type: client_credentials
    if oauth_grant_type == "client_credentials":
        payload = {'grant_type': oauth_grant_type, 'client_id': oauth_client_id, 'client_secret': oauth_client_secret}

        try:
            r = requests.post(url, headers=headers, json=payload, verify=False, timeout=2)
            r.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        json_response = json.loads(r.text)

        return json_response

def get_api_role(clearpass_fqdn, token_type, access_token):
    """Get the current ClearPass operator profile name"""

    url = "https://" + clearpass_fqdn + "/api/oauth/me"

    headers = {'Content-Type':'application/json', "Authorization": "{} {}".format(token_type, access_token)}

    try:
        r = requests.get(url, headers=headers, verify=False, timeout=2)
        r.raise_for_status()
    except Exception as e:
        print(e)
        exit(1)

    json_response = json.loads(r.text)

    return json_response


def get_privs(clearpass_fqdn, token_type, access_token):
    """Get the current access privileges"""

    url = "https://" + clearpass_fqdn + "/api/oauth/privileges"

    headers = {'Content-Type':'application/json', "Authorization": "{} {}".format(token_type, access_token)}

    try:
        r = requests.get(url, headers=headers, verify=False, timeout=2)
        r.raise_for_status()
    except Exception as e:
        print(e)
        exit(1)

    json_response = json.loads(r.text)

    return json_response


check_config(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret, oauth_username, oauth_password)

token_response = get_access_token(clearpass_fqdn, oauth_grant_type, oauth_client_id, oauth_client_secret, oauth_username, oauth_password)
access_token = token_response['access_token']
token_type = token_response['token_type']
token_expires_in = token_response['expires_in']
scope = token_response['scope']

get_api_role_response = get_api_role(clearpass_fqdn, token_type, access_token)
api_role = get_api_role_response['info']

get_privs_response = get_privs(clearpass_fqdn, token_type, access_token)
api_privs = get_privs_response['privileges']


####################################################################
###  FIND ENDPOINTS WITH ATTRIBUTE SOURCE:MOBILEIRON
####################################################################

filter_string = str("%7B%22Source%22%3A%20%22MobileIron%22%7D&limit=25&calculate_count=true")

url = "https://" + clearpass_fqdn + "/api/endpoint?filter=" + filter_string
#print(url)
headers = {'Accept': 'application/json', "Authorization": "{} {}".format(token_type, access_token)}
get_endpoint = requests.get(url, headers=headers, verify=False, timeout=2)
#pprint.pprint(get_endpoint.json())

print("Finding endpoints with attribute Source:MobileIron")
print("")
for key in get_endpoint.json()['_embedded']['items']:
    print("Endpoint ID: {:<15} has MAC address: {:<18} and MDM Source is {}".format(key['id'], key['mac_address'], key['attributes']['Source']))
print("")

####################################################################
### COUNT IS GET VIA "CALCULATE_COUNT=TRUE" IN FILTER_STRING
####################################################################
total_count = str(get_endpoint.json()['count'])
print("TOTAL NUMBERS OF ENDPOINTS: " + total_count)

####################################################################
### POLL CONTEXT SERVER
####################################################################
context_server_name = str(input('ENTER ENDPOINT CONTEXT SERVER NAME: '))
url = "https://" + clearpass_fqdn + "/api/endpoint-context-server/server-name/" + context_server_name + "/trigger-poll"
headers = {'Accept': 'application/json', "Authorization": "{} {}".format(token_type, access_token)}

trigger_poll = requests.patch(url, headers=headers, verify=False, timeout=2)

if trigger_poll.status_code == 204:
    print("")
    print("POLLING THE CONTEXT SERVER WAS SUCCESSFUL. CHECK THE EVENT LOG")
else:
    print("SOMETHING WENT WRONG! ERROR CODE = {}".format(trigger_poll.status_code))
    print("")