from Lib.common import BaseParser, ET, csv
import re

class PowerShellParser(BaseParser):
    """
    Parser for Windows PowerShell Operational events.
    """
    DESC_MAP = {'400': 'PowerShell command executed'}

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
                evdata_str = '; '.join(f"{k}={v}" for k, v in evdata.items()) or '-'

                # Extract raw command from last <Data>
                data_nodes = root.findall('.//ev:EventData/ev:Data', ns)
                raw_text = data_nodes[-1].text.strip() if data_nodes and data_nodes[-1].text else ''

                # Dispatch to handler
                details, extip = self._dispatch(event_id, raw_text)

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

    def _dispatch(self, event_id: str, raw_text: str) -> tuple[str, str]:
        """
        Route to the correct handler based on event_id.
        Returns (details, extip).
        """
        if event_id == '400':
            return self._handle_400(raw_text)
        return '-', '-'

    def _handle_400(self, raw_text: str) -> tuple[str, str]:
        """
        Handle PowerShell command extraction for Event ID 400.
        """
        details = self.extract_command_line(raw_text)
        return details, '-'

    def extract_command_line(self, text: str) -> str:
        """
        Extract substring between HostApplication= and EngineVersion=.
        """
        match = re.search(r"HostApplication=(.*?)EngineVersion=", text, re.DOTALL)
        return match.group(1).strip() if match else '-'
