# Lib/common.py
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import csv
from datetime import datetime
import ipaddress

class BaseParser:
    """
    Abstract base parser encapsulating common logic:
    - Open/close EVTX log
    - Open/close CSV output
    - Namespace extraction
    - Timestamp parsing
    - EventData parsing
    - Public IP check
    """
    def __init__(self, evtx_path: str, csv_path: str):
        self.evtx_path = evtx_path
        self.csv_path = csv_path

    def open_log(self):
        """Open EVTX file for reading."""
        return evtx.Evtx(self.evtx_path)

    def open_csv(self):
        """Open CSV file for writing."""
        return open(self.csv_path, 'w', newline='', encoding='utf-8')

    @staticmethod
    def get_namespaces(root: ET.Element) -> dict:
        """Extract default and user-data namespaces from XML root."""
        tag = root.tag
        ev_ns = tag[1:].split('}')[0] if tag.startswith('{') else ''
        ud_ns = ''
        for elem in root.iter():
            if elem.tag.endswith(('EventXML','EventData')) and elem.tag.startswith('{'):
                ud_ns = elem.tag[1:].split('}')[0]
                break
        return {'ev': ev_ns, 'ud': ud_ns}

    @staticmethod
    def safe_find_text(element: ET.Element, path: str, ns: dict) -> str:
        """Safely find text for given path and namespaces, return '-' if missing."""
        if element is None:
            return '-'
        node = element.find(path, ns)
        return node.text.strip() if node is not None and node.text else '-'

    @staticmethod
    def parse_timestamp(root: ET.Element, ns: dict) -> str:
        """Parse TimeCreated/SystemTime to formatted 'YYYY-MM-DD HH:MM:SS'."""
        tc = root.find('.//ev:System/ev:TimeCreated', ns)
        if tc is not None:
            sts = tc.get('SystemTime','').split('.')[0]
            try:
                return datetime.strptime(sts, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                return sts.replace('T',' ')
        return '-'

    @staticmethod
    def parse_event_data(root: ET.Element, ns: dict) -> dict:
        """Parse all <Data Name=> elements under EventData into a dict."""
        data = {}
        ed = root.find('.//ev:System/ev:EventData', ns) or root.find('.//ev:EventData', ns)
        if ed is not None:
            for d in ed.findall('ev:Data', ns):
                k = d.get('Name','-')
                v = d.text.strip() if d.text else '-'
                data[k] = v
        return data

    @staticmethod
    def is_public_ip(addr: str) -> bool:
        """Return True if addr is a public (non-private) IP address."""
        try:
            ip = ipaddress.ip_address(addr)
            return not (ip.is_private or ip.is_loopback or ip.is_reserved)
        except ValueError:
            return False