import hashlib
import requests
import urllib.parse
import xml.etree.ElementTree as ET

from datetime import datetime

XML_SCHEMA = "http://www.hikvision.com/ver20/XMLSchema"


def sha256(input_string: str) -> str:
    sha256 = hashlib.sha256(input_string.encode())
    return sha256.hexdigest()


class IncorrectResponseContentError(Exception):
    def __init__(self):
        super().__init__("Response content is not in expected form.")


class UnexpectedResponseCodeError(Exception):
    def __init__(self, responseCode, responseText):
        super().__init__(
            f"Unexpected response status code {responseCode} returned with message {responseText}"
        )


class AuthError(UnexpectedResponseCodeError):
    pass


class Endpoints:
    Session_Capabilities = "/ISAPI/Security/sessionLogin/capabilities?username="
    Session_Login = "/ISAPI/Security/sessionLogin"
    Alarm_Disarm = "/ISAPI/SecurityCP/control/disarm/{}"
    Alarm_ArmAway = "/ISAPI/SecurityCP/control/arm/{}?ways=away"
    Alarm_ArmHome = "/ISAPI/SecurityCP/control/arm/{}?ways=stay"
    SubSystemStatus = "/ISAPI/SecurityCP/status/subSystems"
    AlertStream = "/ISAPI/Event/notification/alertStream"
    DetectorConfig = "/ISAPI/SecurityCP/BasicParam/DetectorCfg"
    DetectorConfigCap = "/ISAPI/SecurityCP/BasicParam/DetectorCfg/capabilities"
    Caps = "/ISAPI/SecurityCP/capabilities"
    CheckResultCap = "/ISAPI/SecurityCP/CheckResult/capabilities"
    CheckResult = "/ISAPI/SecurityCP/CheckResult"
    ConfCap = "/ISAPI/SecurityCP/Configuration/capabilities"
    ZoneConfig = "/ISAPI/SecurityCP/Configuration/zones"
    DeviceTime = "/ISAPI/SecurityCP/Configuration/deviceTime"
    EventRecordCap = "/ISAPI/SecurityCP/Configuration/eventRecord/channels/2/capabilities"
    EventRecord = "/ISAPI/SecurityCP/Configuration/eventRecord/channels/1"
    FaultCheck = "/ISAPI/SecurityCP/Configuration/faultCheckCfg"
    GlassBreakDetector = "/ISAPI/SecurityCP/Configuration/glassBreakDetector/zone/5"
    MagneticContact = "/ISAPI/SecurityCP/Configuration/magneticContact/zone/0"
    PublicSubSystem = "/ISAPI/SecurityCP/Configuration/publicSubSys"
    ZonesCap = "/ISAPI/SecurityCP/Configuration/zones/capabilities"
    Zones = "/ISAPI/SecurityCP/Configuration/zones/"
    ArmStatus = "/ISAPI/SecurityCP/status/armStatus"
    StatusCap = "/ISAPI/SecurityCP/status/capabilities"
    HostStatus = "/ISAPI/SecurityCP/status/host"
    PeripheralsStatus = "/ISAPI/SecurityCP/status/exDevStatus"
    ZoneStatus = "/ISAPI/SecurityCP/status/zones"
    BypassZone = "/ISAPI/SecurityCP/control/bypass/{}"
    RecoverBypassZone = "/ISAPI/SecurityCP/control/bypassRecover/{}"
    InterfacesInfo = "/ISAPI/System/Network/interfaces"
    AreaArmStatus = "/ISAPI/SecurityCP/status/armStatus"
    BatteriesStatus = "/ISAPI/SecurityCP/status/batteries"
    SirenStatus = "/ISAPI/SecurityCP/status/sirenStatus"
    SirenTest = "/ISAPI/SecurityCP/Configuration/wirelessSiren/{}/ctrl"
    RepeaterStatus = "/ISAPI/SecurityCP/status/repeaterStatus"
    KeypadStatus = "/ISAPI/SecurityCP/status/keypadStatus"


class Method:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'


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

    def _auth(self):
        q_user = urllib.parse.quote(self.username)
        q_password = urllib.parse.quote(self.password)

        # Step 1: Get XML auth data with panel username and password
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

        # Step 2: Authenticate with XML and save cookies
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

    def url(self, endpoint):
        return f'http://{self.host}{endpoint}'

    def json_url(self, endpoint):
        url = self.url(endpoint)
        param_prefix = "&" if "?" in endpoint else "?"
        return f'{url}{param_prefix}format=json'

    def make_request(self, url, method=Method.GET, data=None, json=None):
        request_func = {
            Method.GET: requests.get,
            Method.POST: requests.post,
            Method.PUT: requests.put
        }[method]

        response = request_func(url, headers={"Cookie": self.cookie}, data=data, json=json)

        if response.status_code == 401:
            self._auth()
            response = self.make_request(url, method, data, json)
        elif response.status_code != 200:
            raise UnexpectedResponseCodeError(response.status_code, response.text)

        return response

    def arm_home(self, sub_id="0xffffffff"):
        return self.make_request(
            self.json_url(Endpoints.Alarm_ArmHome.format(sub_id)),
            method=Method.PUT
        ).json()

    def arm_away(self, sub_id="0xffffffff"):
        return self.make_request(
            self.json_url(Endpoints.Alarm_ArmAway.format(sub_id)),
            method=Method.PUT
        ).json()
    
    def disarm(self, sub_id="0xffffffff"):
        return self.make_request(
            self.json_url(Endpoints.Alarm_Disarm.format(sub_id)),
            method=Method.PUT
        ).json()
    
    def bypass_zone(self, zone_id):
        return self.make_request(
            self.json_url(Endpoints.BypassZone.format(zone_id)),
            method=Method.PUT
        ).json()

    def recover_bypass_zone(self, zone_id):
        return self.make_request(
            self.json_url(Endpoints.RecoverBypassZone.format(zone_id)),
            method=Method.PUT
        ).json()

    def get_area_arm_status(self, area_ids):
        return self.make_request(
            self.json_url(Endpoints.AreaArmStatus),
            Method.POST,
            json={"SubSysList": [{"SubSys": {"id": area_id}} for area_id in area_ids]}
        ).json()
    
    def siren_test(self, siren_id):
        return self.make_request(
            self.json_url(Endpoints.SirenTest.format(siren_id)),
            method=Method.PUT,
            json={"SirenCtrl": {"operation":"start"}}
        ).json()
    
    def batteries_status(self):
        return self.make_request(self.json_url(Endpoints.BatteriesStatus)).json()
    
    def peripherals_status(self):
        return self.make_request(self.json_url(Endpoints.PeripheralsStatus)).json()

    def zone_status(self):
        return self.make_request(self.json_url(Endpoints.ZoneStatus)).json()

    def subsystem_status(self):
        return self.make_request(self.json_url(Endpoints.SubSystemStatus)).json()

    def host_status(self):
        return self.make_request(self.json_url(Endpoints.HostStatus)).json()

    def siren_status(self):
        return self.make_request(self.json_url(Endpoints.SirenStatus)).json()

    def keypad_status(self):
        return self.make_request(self.json_url(Endpoints.KeypadStatus)).json()

    def repeater_status(self):
        return self.make_request(self.json_url(Endpoints.RepeaterStatus)).json()

    def get_interfaces_info(self):
        return self.make_request(self.url(Endpoints.InterfacesInfo)).text
