from typing import Optional, Any

import hashlib
import requests
import logging
import urllib.parse
import xml.etree.ElementTree as ET

from datetime import datetime

from endpoints import Endpoints

XML_SCHEMA = "http://www.hikvision.com/ver20/XMLSchema"

def get_mac_address_of_interface(xml_data, interface_id):
    try:
        root = ET.fromstring(xml_data)
        namespaces = {'xmlns': XML_SCHEMA}        
        for ni_element in root.findall('xmlns:NetworkInterface', namespaces):
            if ni_element.find('xmlns:id', namespaces).text == str(interface_id):
                link_elm = ni_element.find('xmlns:Link', namespaces)
                return link_elm.find('xmlns:MACAddress', namespaces).text
    except Exception as ex:
        return ''
    
    return ''


def sha256(input_string: str) -> str:
    sha256 = hashlib.sha256(input_string.encode())
    return sha256.hexdigest()

class IncorrectResponseContentError(Exception):
    def __init__(self):
        super().__init__("Response content is not in expected form.")    

class UnexpectedResponseCodeError(Exception):
    def __init__(self, responseCode, responseText):
        super().__init__(f"Unexpected response status code {responseCode} returned with message {responseText}")

class AuthError(UnexpectedResponseCodeError):
    pass


class Method:
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


class SessionLoginCap:
    def __init__(self, session_id, challenge, salt, salt2, is_irreversible, iteration, username, password):
        self.session_id = session_id
        self.challenge = challenge
        self.salt = salt
        self.salt2 = salt2
        self.is_irreversible = is_irreversible
        self.iteration = iteration
        
        self.username = username
        self.password = password

    def encode_password(self):
        if self.is_irreversible:
            result = sha256(f"{self.username}{self.salt}{self.password}")
            result = sha256(f"{self.username}{self.salt2}{result}")
            result = sha256(f"{result}{self.challenge}")

            for i in range(2, self.iteration):
                result = sha256(result)
        else:
            result = f"{sha256(self.password)}{self.challenge}"

            for i in range(1, self.iteration):
                result = sha256(result)

        return result
    
    def auth_xml(self):
        root = ET.Element('SessionLogin')
        
        child1 = ET.SubElement(root, 'sessionID')
        child1.text = self.session_id
        child2 = ET.SubElement(root, 'userName')
        child2.text = self.username
        child3 = ET.SubElement(root, 'password')
        child3.text = self.encode_password()
        child4 = ET.SubElement(root, 'sessionIDVersion')
        child4.text = "2.1"

        return ET.tostring(root, encoding='utf-8', method='xml')
        

class AxPro:
    """HikVisison Ax Pro Alarm panel coordinator."""

    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.cookie = ''


    def auth(self):
        q_user = urllib.parse.quote(self.username)
        q_password = urllib.parse.quote(self.password)
        response = requests.get(f"http://{q_user}:{q_password}@{self.host}{Endpoints.Session_Capabilities}{q_user}")

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            namespaces = {'xmlns': XML_SCHEMA}
            session_id = root.findtext("xmlns:sessionID", default=None, namespaces=namespaces)
            challenge = root.findtext("xmlns:challenge", default=None, namespaces=namespaces)
            salt = root.findtext("xmlns:salt", default=None, namespaces=namespaces)
            salt2 = root.findtext("xmlns:salt2", default=None, namespaces=namespaces)
            is_irreversible = root.findtext("xmlns:isIrreversible", default=False, namespaces=namespaces)
            iterations = root.findtext("xmlns:iterations", default=None, namespaces=namespaces)
        else:
            raise IncorrectResponseContentError
        
        session_cap = SessionLoginCap(
            session_id=session_id,
            challenge=challenge,
            salt=salt,
            salt2=salt2,
            is_irreversible=is_irreversible,
            iteration=int(iterations) if iterations is not None else None,
            username=self.username,
            password=self.password
        )
        xml = session_cap.auth_xml()

        # Try to authenticate
        timestamp = datetime.now().timestamp()
        session_login_url = f"http://{self.host}{Endpoints.Session_Login}?timeStamp={int(timestamp)}"
        login_response = requests.post(session_login_url, xml)

        if login_response.status_code == 200:
            cookie = login_response.headers.get("Set-Cookie")

            if cookie is None:
                root = ET.fromstring(login_response.text)
                namespaces = {'xmlns': XML_SCHEMA}
                session_id = root.findtext("xmlns:sessionID", default=None, namespaces=namespaces)
                if session_id is not None:
                    cookie = "WebSession=" + session_id
            else:
                self.cookie = cookie.split(";")[0]

            if cookie is None:
                raise Exception("No cookie provided")

            self.cookie = cookie
        else:
            raise AuthError(login_response.status_code, login_response.text)
        
        
    @staticmethod
    def build_url(endpoint, is_json):
        param_prefix = "&" if "?" in endpoint else "?"
        return f"{endpoint}{param_prefix}format=json" if is_json else endpoint

    def _base_json_request(self, url: str, method: Method = Method.GET, data=None):
        endpoint = self.build_url(url, True)
        response = self.make_request(endpoint, method, is_json=True, data=data)

        if response.status_code != 200:
            raise UnexpectedResponseCodeError(response.status_code, response.text)
        if response.status_code == 200:
            return response.json()

    def make_request(self, endpoint, method, data=None, is_json=False):
        headers = {"Cookie": self.cookie}

        if method == Method.GET:
            response = requests.get(endpoint, headers=headers)
        elif method == Method.POST:
            if is_json:
                response = requests.post(endpoint, json=data, headers=headers)
            else:
                response = requests.post(endpoint, data=data, headers=headers)
        elif method == Method.PUT:
            if is_json:
                response = requests.put(endpoint, json=data, headers=headers)
            else:
                response = requests.put(endpoint, data=data, headers=headers)
        else:
            return None

        if response.status_code == 401:
            self.auth()
            response = self.make_request(endpoint, method, data, is_json)

        return response

    def arm_home(self, sub_id: Optional[int] = None):
        sid = "0xffffffff" if sub_id is None else str(sub_id)
        return self._base_json_request(f"http://{self.host}{Endpoints.Alarm_ArmHome.replace('{}', sid)}",
                                       method=Method.PUT)

    def arm_away(self, sub_id: Optional[int] = None):
        sid = "0xffffffff" if sub_id is None else str(sub_id)
        return self._base_json_request(f"http://{self.host}{Endpoints.Alarm_ArmAway.replace('{}', sid)}",
                                       method=Method.PUT)

    def disarm(self, sub_id: Optional[int] = None):
        sid = "0xffffffff" if sub_id is None else str(sub_id)
        return self._base_json_request(f"http://{self.host}{Endpoints.Alarm_Disarm.replace('{}', sid)}",
                                       method=Method.PUT)

    def subsystem_status(self):
        return self._base_json_request(f"http://{self.host}{Endpoints.SubSystemStatus}")

    def peripherals_status(self):
        return self._base_json_request(f"http://{self.host}{Endpoints.PeripheralsStatus}")

    def zone_status(self):
        endpoint = f"http://{self.host}{Endpoints.ZoneStatus}"
        endpoint = self.build_url(endpoint, True)
        response = self.make_request(endpoint, Method.GET)

        if response.status_code != 200:
            raise UnexpectedResponseCodeError(response.status_code, response.text)

        return response.json()

    def bypass_zone(self, zone_id):
        endpoint = f"http://{self.host}{Endpoints.BypassZone}{zone_id}"
        endpoint = self.build_url(endpoint, True)
        response = self.make_request(endpoint, Method.PUT)

        if response.status_code != 200:
            raise UnexpectedResponseCodeError(response.status_code, response.text)

        return response.status_code == 200

    def recover_bypass_zone(self, zone_id):
        endpoint = f"http://{self.host}{Endpoints.RecoverBypassZone}{zone_id}"
        endpoint = self.build_url(endpoint, True)
        response = self.make_request(endpoint, Method.PUT)

        return response.status_code == 200

    def get_interface_mac_address(self, interface_id):
        endpoint = f"http://{self.host}{Endpoints.InterfaceInfo}"

        response = self.make_request(endpoint, Method.GET)

        if response.status_code == 200:
            return get_mac_address_of_interface(response.text, interface_id)

        return ''

    def get_area_arm_status(self, area_id):
        endpoint = f"http://{self.host}{Endpoints.AreaArmStatus}"
        endpoint = self.build_url(endpoint, True)

        data = {"SubSysList": [{"SubSys": {"id": area_id}}]}

        response = self.make_request(endpoint, Method.POST, data=data, is_json=True)

        try:
            if response.status_code == 200:
                response_json = response.json()
                return response_json["ArmStatusList"][0]["ArmStatus"]["status"]
        except:
            return ''
        return ''

    def host_status(self):
        return self._base_json_request(f"http://{self.host}{Endpoints.HostStatus}")

    def siren_status(self):
        return self._base_json_request(f"http://{self.host}{Endpoints.SirenStatus}")

    def keypad_status(self):
        return self._base_json_request(f"http://{self.host}{Endpoints.KeypadStatus}")

    def repeater_status(self):
        return self._base_json_request(f"http://{self.host}{Endpoints.RepeaterStatus}")
