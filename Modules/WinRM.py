from Lib.common import BaseParser, ET, csv

class WinRMParser(BaseParser):
    """
    Parser for WinRM Operational events.
    """
    DESC_MAP = {
        '132': 'WSMan operation completed',
        '145': 'WSMan operation started'
    }

    def parse(self):
        with self.open_log() as log, self.open_csv() as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                'Timestamp', 'Logged', 'Hostname', 'ExtIP',
                'Description', 'Details', '-', 'SourceFile'
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

                # Dispatch to handler
                details, extip = self._dispatch(event_id, evdata)

                writer.writerow([
                    timestamp,
                    'Logged',
                    hostname or '-',
                    extip,
                    self.DESC_MAP[event_id],
                    details,
                    '-',
                    self.evtx_path.split('\\')[-1]
                ])

    def _dispatch(self, event_id: str, evdata: dict) -> tuple[str, str]:
        """
        Route to the correct handler based on event_id.
        Returns (details, extip).
        """
        if event_id == '132':
            return self._handle_132(evdata)
        if event_id == '145':
            return self._handle_145(evdata)
        return '-', '-'

    def _handle_132(self, evdata: dict) -> tuple[str, str]:
        """
        Handle WSMan operation completed (132).
        """
        operation = evdata.get('operationName', '-')
        details = f"WSMan operation '{operation}' completed."
        return details, '-'

    def _handle_145(self, evdata: dict) -> tuple[str, str]:
        """
        Handle WSMan operation started (145).
        """
        operation   = evdata.get('operationName', '-')
        resource_uri = evdata.get('resourceUri', '-')
        details = (
            f"WSMan operation '{operation}' started on ResourceUri '{resource_uri}'."
        )
        return details, '-'