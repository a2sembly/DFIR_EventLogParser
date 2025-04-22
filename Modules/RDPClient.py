from Lib.common import BaseParser, ET, csv

class TerminalServicesCAXParser(BaseParser):
    """
    Parser for TerminalServices-RDPClient events.
    """
    DESC_MAP = {
        '1024': 'RDP outbound connection attempt',
        '1026': 'RDP outbound disconnection'
    }

    def parse(self):
        with self.open_log() as log, self.open_csv() as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                'Timestamp', 'Logged', 'Hostname', 'ExtIP',
                'Description', 'Details', 'EventData', 'SourceFile'
            ])

            for record in log.records():
                root = ET.fromstring(record.xml())
                ns = self.get_namespaces(root)

                event_id = self.safe_find_text(root, './/ev:System/ev:EventID', ns)
                if event_id not in self.DESC_MAP:
                    continue

                timestamp = self.parse_timestamp(root, ns)
                hostname = self.safe_find_text(root, './/ev:System/ev:Computer', ns)

                # Parse EventData once
                evdata = self.parse_event_data(root, ns)
                extip = self._get_extip(evdata)
                details = self._get_details(evdata)
                evdata_str = '; '.join(f"{k}={v}" for k, v in evdata.items()) or '-'

                writer.writerow([
                    timestamp,
                    'Logged',
                    hostname or '-',
                    extip,
                    self.DESC_MAP[event_id],
                    details,
                    evdata_str,
                    self.evtx_path.split('\\')[-1]
                ])

    def _get_extip(self, evdata: dict) -> str:
        """
        Determine external IP from EventData value field.
        """
        val = evdata.get('Value', '-')
        return val if self.is_public_ip(val) else '-'

    def _get_details(self, evdata: dict) -> str:
        """
        Build the details string for RDPClient events.
        """
        name = evdata.get('Name', '-')
        value = evdata.get('Value', '-')
        return f"Name: {name}, Value: {value}"
