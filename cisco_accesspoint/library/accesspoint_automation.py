#!/usr/bin/python

from ansible_collections.cisco.dnac.plugins.module_utils.dnac import DnacBase
from ansible.module_utils.basic import AnsibleModule

import pandas as pd
import urllib3, sys, requests
from urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth
from pydantic import ValidationError 

from uuid import UUID, uuid4
from enum import Enum
from typing_extensions import Annotated
from pydantic import BaseModel, AnyHttpUrl, Field
from pydantic.networks import IPvAnyAddress
from pydantic.functional_validators import AfterValidator
from pydantic_extra_types.mac_address import MacAddress

__metaclass__ = type
__author__ = ("A Mohamed Rafeek, Natarajan")

DOCUMENTATION = r"""
---
module: accesspoint_automation
short_description: accesspoint_automation used to automate bulk AP configuration changes.
description:
- We can change the AP display name, AP name or Other Param based on the input.yml file
- Using by this package we can filter specific device details like family = Switches and Hubs
- We can compare input details with current AP configuration .
- Desired configuration will be updated to the needed APs Only
- Also able to reboot the Accesspoint if needed.
version_added: '7.0.0'
extends_documentation_fragment:
  - accesspoint_automation
author: A Mohamed Rafeek (@mohamedrafeek)
        Natarajan (@natarajan)

accesspoints:
    macAddress: It is string MAC address format
      managementIpAddress: String IP address format
      accesspointradiotype: It is number and should be 1,2,3 and 6
        1 - Will be 2.4 Ghz
        2 - Will be 5 Ghz
        3 - Will be XOR
        6 - Will be 6 Ghz
      apName: It should be String

requirements:
- dnacentersdk == 2.4.5
- python >= 3.10
notes:
  - SDK Method used are
    cisco_accesspoint.accesspoint_automation.DnacAutomation,

  - Paths used are
    post /api/system/v1/auth/token
    get /dna/intent/api/v1/network-device
    get /dna/intent/api/v1/wireless/accesspoint-configuration/summary?key=
    post /dna/intent/api/v1/wireless/accesspoint-configuration
    post /dna/intent/api/v1/device-reboot/apreboot
"""

EXAMPLES = r"""
- name: Configure device credentials on Cisco DNA Center
  hosts: localhost
  connection: local
  gather_facts: no
  vars_files:
    - "credentials.yml"
    - "input.yml"
    - "urls.yml"
  tasks:
    - name: Get Device info and updating access point details
      accesspoint_automation:
        auth_url: "{{auth_url}}"
        dnac_device_url: "{{dnac_device_url}}"
        ap_config_get_url: "{{ap_config_get_url}}"
        ap_config_update_url: "{{ap_config_update_url}}"
        ap_reboot_url: "{{ap_reboot_url}}"
        display_selection: "{{display_selection}}"
        device_filterfield: "{{device_filterfield}}"
        device_filter_string: "{{device_filter_string}}"
        device_fields: "{{device_fields}}"
        ap_selected_field: "{{ap_selected_field}}"
        dnac_host: "{{dnac_host}}"
        dnac_username: "{{dnac_username}}"
        dnac_password: "{{dnac_password}}"
        dnac_verify: "{{dnac_verify}}"
        dnac_port: "{{dnac_port}}"
        dnac_version: "{{dnac_version}}"
        dnac_debug: "{{dnac_debug}}"
        dnac_log: True
        dnac_log_level: DEBUG
        config_verify: True
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        accesspoints: "{{ accesspoints }}"
      register: output_list
    - name: iterate through module output (a list)
      debug:
        msg: '{{ item }}'   
        with_items: "{{output_list.output }}"
"""

RETURN = r"""
#Case: Modification of the AP details updated and Rebooted Accesspoint
response:
  description: A dictionary with activation details as returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
        "response": {
            "taskId": "string",
            "url": "string"
        },
        "version": "string"
    }
"""

class DnacAutomation(DnacBase):
    """Class containing member attributes for DNAC Access Point Automation module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged"]
        self.payload = module
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.verify = False

    def validate_input(self, inputdata):
        """
        Validate the fields provided in the yml files.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types based pydentics package.
        Parameters:
          - inputdata: To validate the input file of yaml keys values will be validated.
        Returns:
          The method not returns anything just validation input if anything worng will stop execution.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
          If the validation succeeds, this will allow to go next step, unless this will stop execution.
          based on the fields.
        """
        self.log('Validating the Yaml File..', "INFO")
        try:
            CheckUrl(hosturl="https://" + inputdata["dnac_host"])
            CheckNames(names=inputdata["dnac_username"])
            CheckNames(names=inputdata["dnac_password"])
            CheckPort(port=inputdata["dnac_port"])
            aplist = inputdata.get("accesspoints")
            for eachap in aplist:
                CheckIPaddress(managementIpAddress=eachap["managementIpAddress"])
                CheckMACaddress(macAddress=eachap["macAddress"])
                CheckRadioType(ap_radiotype=int(eachap["accesspointradiotype"]))
        except ValidationError as e:
            self.log("Invalid Param provided in input Yml File." + str(e) + str(sys.exc_info()), "ERROR")
            exit()

    def get_authenticate(self, url = None, user = None, passwd = None):
        """
        This function used to validate the user name and password of DNAC site to get device information.
        also you can re use this function for basic authentication available on any URL.
        Useally this will return the Token.
        Parameters:
          - url: To validate the which websites need to be login eg:- https://sandboxdnac.cisco.com/api/system/v1/auth/token.
          - user: User name of domain names. eg:  devnetuser
          - passwd: Password of domain names. eg:  Cisco123!
        Returns:
          This will be return the token .
        Example:
            functions = DnacAutomation(module)
            auth_url = https://sandboxdnac.cisco.com/api/system/v1/auth/token
            token = functions.get_authenticate(auth_url, username, password)
        """
        urllib3.disable_warnings(InsecureRequestWarning)
        dnac_auth = HTTPBasicAuth(user, passwd)
        try:
            self.log(f'Authenticating with user id : {user}', "INFO")
            response = requests.post(url, auth=dnac_auth,  headers=self.headers, verify=self.verify)
            token = response.json().get("Token")
            if token == None:
                self.log(str(response.json()['error']) + str(sys.exc_info()), "ERROR")
        except Exception as e:
            self.log(str(e) + str(sys.exc_info()), "ERROR")
            token = None
        return token

    def get_network_info(self, token, url, payload):
        """
        This function used to get all device details as json response from DNAC site.
        Parameters:
          - url: Url of the Dnac site eg:- https://sandboxdnac.cisco.com/dna/intent/api/v1/network-device.
          - Token: validated string 
          - payload: used from yml input files like, urls.yml, credentials.yml and input.yml
        Returns:
          {
            'family': 'Switches and Hubs', 'type': 'Cisco Catalyst 9000 UADP 8 Port Virtual Switch',
            'description': 'Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9KV_IOSXE), Experimental Version 17.9.20220318:182713 [BLD_POLARIS_DEV_S2C_20220318_081310-10-g847b433944c4:/nobackup/rajavenk/vikagarw/git_ws/polaris_dev 101] Copyright (c) 1986-2022 by Cis', 4
            'lastUpdateTime': 1713755121303, 'macAddress': '52:54:00:01:c2:c0', 
            'deviceSupportLevel': 'Supported', 'softwareType': 'IOS-XE', 'softwareVersion': '17.9.20220318:182713', 'serialNumber': '9SB9FYAFA2O', 'collectionInterval': 'Global Default', 'managementState': 'Managed', 'upTime': '28 days, 0:13:42.00', 'roleSource': 'AUTO', 'lastUpdated': '2024-04-22 03:05:21', 'bootDateTime': '2024-03-25 02:52:21', 'series': 'Cisco Catalyst 9000 Series Virtual Switches', 'snmpContact': '', 'snmpLocation': '', 'apManagerInterfaceIp': '', 'collectionStatus': 'Partial Collection Failure', 'hostname': 'sw1', 'locationName': None, 'managementIpAddress': '10.10.20.175', 'platformId': 'C9KV-UADP-8P', 'reachabilityFailureReason': 'SNMP Connectivity Failed', 'reachabilityStatus': 'Unreachable', 'associatedWlcIp': '', 'apEthernetMacAddress': None, 'errorCode': 'DEV-UNREACHED', 'errorDescription': 'NCIM12013: SNMP timeouts are occurring with this device. }
        Example:
            functions = DnacAutomation(module)
            url = https://sandboxdnac.cisco.com/dna/intent/api/v1/network-device.
            device_data = functions.get_network_info(token, url, payload)
        """
        self.log('Getting Network Device information', "INFO")
        self.headers["X-Auth-Token"] = str(token)
        try:
            response = requests.get(url, headers=self.headers, verify=self.verify)
            jsondata = response.json().get("response")
            return self.parse_json_data(jsondata, payload)
        except Exception as e:
            self.log(str(response.json()['error']) + e + str(sys.exc_info()), "ERROR")

    def parse_json_data(self, json_data, payload):
        """
        This function used from inside the get_network_info function for customize the dnac device information data
        based on the display_selection number it should be 1,2,3,4or 5 
        display_selection : 1 :-
            This will show the all fields of the device info no filter
        display_selection : 2 :-
            This will show only filtered data based on the specific field mentioned in the urls.yml
            device_filterfield: "hostname"  # single field no comma
            device_filter_string: "sw2,sw1" # Full value like 'hostname': 'sw3'
        display_selection : 3 :-
            This will show only the fields need to be displayed from the device data no filter will be applied
            any customization required can update in the urls.yml file
            device_fields: "id,family,type,macAddress,managementIpAddress"
        display_selection : 4 :-
            This field combination of the 2 and 3, when used 4 need to give all below 3 fields
            device_filterfield: "hostname"  # single field no comma
            device_filter_string: "sw2,sw1" # Full value like 'hostname': 'sw3'
            device_fields: "id,family,type,macAddress,managementIpAddress"
        display_selection : 5 :-
            This field combination of 2 & 3 also multiple field can be filtered  used pandas package
            device_fields: "id,family,type,macAddress,managementIpAddress" # this must be given
            device_filterfield: "hostname,macAddress" # List of field need to be filter given by comma seperater
            device_filter_string: "sw2,sw1|52:54:00:0e:1c:6a" # added | seperated based on the list of field need filter
        Parameters:
          - json_data: this is respose of the all device details geting from device info url. 
          - payload: used from yml input files like, urls.yml, credentials.yml and input.yml
        Returns:
            {
            'id': 'c069bc2c-bfa3-47ef-a37e-35e2f8ed3f01'
            'family': 'Switches and Hubs',
            'type': 'Cisco Catalyst 9000 UADP 8 Port Virtual Switch',
            'macAddress': '52:54:00:01:c2:c0', 
            'managementIpAddress': '10.10.20.175'
            }
        Example:
            self.parse_json_data(jsondata, payload)
        """
        if payload['display_selection'] == 1:
            return json_data
        elif payload['display_selection'] == 2:
            field = payload['device_filterfield']
            types = [str(x) for x in payload['device_filter_string'].split(",")]
            if field != None:
                filtered_data = [data for data in json_data if data[field] in types]
                return filtered_data
            else:
                self.log('No data in filterfield', "ERROR")
                return None
        elif payload['display_selection'] == 3:
            fields = [str(x) for x in payload['device_fields'].split(",")]
            df = pd.DataFrame.from_records(json_data)
            selected_fields = df[fields]
            return selected_fields.to_dict('records')
        elif payload['display_selection'] == 4:
            fields = [str(x) for x in payload['device_fields'].split(",")]
            field = payload['device_filterfield']
            types = [str(x) for x in payload['device_filter_string'].split(",")]
            if field != None:
                filtered_data = [data for data in json_data if data[field] in types]
                if len(fields) > 0:
                    new_list = []
                    for data in filtered_data:
                        new_dict = {key: value for key, value in data.items() if key in fields}
                        new_list.append(new_dict)
                    return new_list
                else:
                    self.log('No data in field', "ERROR")
                    return None
        elif payload['display_selection'] == 5:
            fields = [str(x) for x in payload['device_fields'].split(",")]
            ffield = [str(x) for x in payload['device_filterfield'].split(",")]
            types = [str(x) for x in payload['device_filter_string'].split("|")]
            df = pd.DataFrame.from_records(json_data)
            count = 0
            for field in ffield:
                eachtypes = [str(x) for x in types[count].split(",")]
                df = df[df[field].isin(eachtypes)]
                count += 1
            selected_fields = df[fields]
            return selected_fields.to_dict('records')

    def get_ap_configuration(self, token, url, device_data, payload = None):
        """
        This function used to get AP device details as json response from DNAC site.
        by giving MAC address as a input in the URL GET Method
        Parameters:
          - url: Url of the AP as eg:- https://sandboxdnac.cisco.com/dna/intent/api/v1/wireless/accesspoint-configuration/summary?key=.
          - Token: validated string
          - device_data: DNAC device data response from get_network_info
          - payload: used from yml input files like, urls.yml, credentials.yml and input.yml
            if ap_selected_field in urls.py is empty or all this will show all field
            else ap_selected_field: "macAddress,displayName,apMode,apName"
            then will show only listed field.
        Returns:
            {
            "macAddress": '52:54:00:01:c2:c0',
            "apName": "string",
            "displayName": "string",
            "apMode": "string"
            }
        Example:
            functions = DnacAutomation(module)
            url = https://sandboxdnac.cisco.com/dna/intent/api/v1/wireless/accesspoint-configuration/summary?key=.
            ap_data = functions.get_ap_configuration(token, url, device_data, payload)
        """
        ap_config_data = []
        self.headers["X-Auth-Token"] = str(token)
        for device in device_data:
            self.log('Getting Access Point Configuration Information' + device['macAddress'], "INFO")
            try:
                response = requests.get(url+device['macAddress'], headers=self.headers, verify=self.verify)
                jsondata = response.json().get("response")
                ap_config_data.append(jsondata)
            except Exception as e:
                self.log(str(response.json()['error']) + e + str(sys.exc_info()), "ERROR")
        if payload["ap_selected_field"] == "" or payload["ap_selected_field"] == "all" : return ap_config_data
        fields = [str(x) for x in payload["ap_selected_field"].split(",")]
        if len(ap_config_data) != 0:
            df = pd.DataFrame.from_records(ap_config_data)
            selected_data = df[fields]
            return selected_data.to_dict('records')
        else:
            return None

    def compare_ap_cofig_with_inputdata(self, apconfig, inputconfig):
        """
        This function used to compare with the input ap detail with the current ap configuration
        information are not same, those data will be updated in the AP input information.
        Parameters:
          - apconfig: This is response of the get_ap_configuration
          - inputconfig: This is AP config change information from input.yml file
        Returns:
            This will be the return the final data for update AP detail.
            [{
                "macAddress": "52:54:00:0f:25:4c",
                "managementIpAddress": "10.10.20.178",
                "accesspointradiotype": 1,
                "apName": "HallAP"},
                {"macAddress": "52:54:00:0e:1c:6a",
                "managementIpAddress": "10.10.20.176",
                "accesspointradiotype": 2,
                "apName": "FloorAP"}]
        Example:
            functions = DnacAutomation(module)
            final_input_data = functions.compare_ap_cofig_with_inputdata(device_data, payload)
        """
        final_apchange = []
        for each_input in inputconfig:
            for eachap in apconfig:
                # We are identifing AP based on the AP mac Address so we cannot update this field.
                if each_input["macAddress"] == eachap["macAddress"]:
                    for each_key in list(each_input.keys()):
                        if each_input[each_key] != eachap[each_key]:
                            final_apchange.append(each_input)
                            break
        if len(final_apchange) > 0:
            return final_apchange
        else:
            self.log('Input Access Point Configuration remains same in the Current AP configration', "INFO")
            exit()

    def update_ap_configuration(self, token, url, device_data):
        """
        This function used to update the ap detail with the current ap configuration
        Final data received from compare_ap_cofig_with_inputdata response will be the 
        input of this function.
        Parameters:
          - url: Url of the AP as eg:- https://sandboxdnac.cisco.com/dna/intent/api/v1/wireless/accesspoint-configuration
          - Token: validated string
          - device_data: DNAC final device data response from compare_ap_cofig_with_inputdata
        Returns:
            {
                "response": {
                    "taskId": "string",
                    "url": "string"
                },
                "version": "string"
            }
        Example:
            functions = DnacAutomation(module)
            final_input_data = functions.update_ap_configuration(token, url, device_data)
        """
        all_response = []
        self.headers["X-Auth-Token"] = str(token)
        for device in device_data:
            payload = {
                "radioConfigurations": [{
                        "radioRoleAssignment": device["radioRoleAssignment"],
                        "radioBand": device["radioBand"]
                    }]
                }
            try:
                self.log('Updating Access Point Configuration Information of ' + device["managementIpAddress"], "INFO")
                response = requests.post(url, headers=self.headers, data = payload, verify=self.verify)
                if response.get("Status") == 200:
                    device["update_status"] == "success"
                    all_response.append(device)
            except Exception as e:
                self.log(str(response.json()['error']) + e + str(sys.exc_info()), "ERROR")

        if len(all_response) > 0:
            return all_response
        else:
            return None

    def reboot_ap_configuration(self, token, url, device_data):
        """
        This function used to reboot the ap after updated the ap information.
        Parameters:
          - url: Url of the AP as eg:- https://sandboxdnac.cisco.com/dna/intent/api/v1/device-reboot/apreboot
          - Token: validated string
          - device_data: DNAC final device data response from update_ap_configuration
            in data of device["update_status"] == success then only this will reboot device.
        Returns:
            {
                "response": {
                    "taskId": "string",
                    "url": "string"
                },
                "version": "string"
            }
        Example:
            functions = DnacAutomation(module)
            final_input_data = functions.reboot_ap_configuration(token, url, device_data)
        """
        response = None
        all_macaddress = []
        self.headers["X-Auth-Token"] = str(token)
        for device in device_data:
            if device["update_status"] == "success":
                all_macaddress.append(device["apMacAddresses"])
        
        if len(all_macaddress) > 0:
            payload = { "apMacAddresses": all_macaddress }
            try:
                self.log('Rebooting below Access Point(s)' + str(all_macaddress.join(", ")), "INFO")
                response = requests.post(url, headers=self.headers, data = payload, verify=self.verify)
            except Exception as e:
                self.log(str(response.json()['error']) + e + str(sys.exc_info()), "ERROR")

        if response.get("Status") == 200:
            self.log('Rebooted below Access Point(s)' + str(all_macaddress.join(", ")), "INFO")
            return response.text.encode('utf8')
        else:
            return None


"""
    All below classes are used for the Pydentic Validation usage.
"""
# This pydentic custom validation like list of family can be update here.
class DeviceFamily(Enum):
    SWITCHHUBS = "Switches and Hubs"

# This is pydentic validation used the validate URL as http:// or https://
class CheckUrl(BaseModel):
    hosturl: AnyHttpUrl

# This is used to validate names should be atlease one letter required.
class CheckNames(BaseModel):
    names: str = Field(min_length=1, frozen=True)

# This used to check the port number usally will be integer
class CheckPort(BaseModel):
    port: int

# Pydentic model is available to check IP address either ipv4 or ipv6
class CheckIPaddress(BaseModel):
    managementIpAddress: IPvAnyAddress

# Pydentic model is available to check MAC address
class CheckMACaddress(BaseModel):
    macAddress: MacAddress

# This is used to check the UUID is correct format of UUID4 type
class CheckUUIDtype(BaseModel):
    id: UUID = Field(default_factory=uuid4, frozen=False)

# To check the given input of Device family in the enum list.
class CheckDeviceFamily(BaseModel):
    family: DeviceFamily

# This custom function added to the pydentic validate the specific radio type
def check_radiotype(v: int) -> int:
    assert v in (1, 2, 3, 6), f'{v} is not a correct Radio Type'
    return v

# This class to check the Radio type in 1,2,3, 6
class CheckRadioType(BaseModel):
    ap_radiotype: Annotated[int, AfterValidator(check_radiotype)]


def main():
    """ main entry point for module execution
    """
    # Basic Ansible type check or assign default.
    element_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin'},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'auth_url': {'required': True, 'type': 'str'},
                    'dnac_device_url': {'required': True, 'type': 'str'},
                    'ap_config_get_url': {'required': True, 'type': 'str'},
                    'ap_config_update_url': {'required': True, 'type': 'str'},
                    'ap_reboot_url': {'required': True, 'type': 'str'},
                    'display_selection': {'required': True, 'type': 'int'},
                    'device_filterfield': {'required': True, 'type': 'str'},
                    'device_filter_string': {'required': True, 'type': 'str'},
                    'device_fields': {'required': True, 'type': 'str'},
                    'ap_selected_field': {'required': True, 'type': 'str'},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    'config_verify': {'type': 'bool', "default": False},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'accesspoints': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'validate_response_schema': {'type': 'bool', 'default': True}
                }
    module = AnsibleModule(
        argument_spec=element_spec,
        supports_check_mode=True
    )

    result = dict(
        changed=False,
        original_message='',
        message='',
        output=[]
    )


    functions = DnacAutomation(module)
    # Check the Input file should not be empty accesspoints param
    if len(module.params.get('accesspoints')) < 1:
        module.fail_json(msg='Access Point Should not be Empty, You may forget to pass input.yml file', **result)
    
    # Validate the value on input.yml file.
    functions.validate_input(module.params)
    https = "https://"

    # Authenticating and response as token
    auth_url = https + module.params['dnac_host'] + module.params['auth_url']
    token = functions.get_authenticate(auth_url, module.params['dnac_username'],
                                      module.params['dnac_password'])
    
    # Get the Device data from DNAC by passing token as input and url details.
    dnac_device_url = https + module.params['dnac_host'] + module.params['dnac_device_url']
    device_data = functions.get_network_info(token, dnac_device_url, module.params)

    """
    # Getting the AP details by passing hte Mac Address of the device
    ap_config_get_url = https + module.params['dnac_host'] + module.params['ap_config_get_url']
    ap_conf_data = functions.get_ap_configuration(token, ap_config_get_url, device_data, module.params)

    # Comparing input data with current AP configuration detail
    final_config = functions.compare_ap_cofig_with_inputdata(ap_conf_data, module.params["accesspoints"])

    # Updating the final filtered data to the update AP url
    ap_config_update_url = https + module.params['dnac_host'] + module.params['ap_config_update_url']
    ap_update_response = functions.update_ap_configuration(token, ap_config_update_url, final_config)

    # Calling Reboot AP configuration.
    ap_reboot_url = https + module.params['dnac_host'] + module.params['ap_reboot_url']
    ap_reboot_response = functions.reboot_ap_configuration(token, ap_reboot_url, ap_update_response)
    """

    # Code to modify input list - Our custom python code
    for item in device_data:
        result['output'].append({"value": print(item), "extra": "n/a"})
    module.exit_json(**result)

if __name__ == '__main__':
    main()
