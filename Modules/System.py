from Lib.common import BaseParser, ET, csv

class SystemParser(BaseParser):
    """
    Parser for Windows System events.
    """
    DESC_MAP = {
        '7036': 'Service state change',
        '7045': 'Service installed',
        '104': 'EventLog cleared'
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

                # Override 'ud' namespace dynamically
                ud_parent = root.find('.//ev:UserData', ns)
                ud_elem = next(iter(ud_parent), None) if ud_parent is not None else None
                ns['ud'] = ud_elem.tag[1:].split('}')[0] if ud_elem is not None and ud_elem.tag.startswith('{') else ''

                event_id = self.safe_find_text(root, './/ev:System/ev:EventID', ns)
                if event_id not in self.DESC_MAP:
                    continue

                # Common parsing
                timestamp = self.parse_timestamp(root, ns)
                hostname = self.safe_find_text(root, './/ev:System/ev:Computer', ns)

                # Parse EventData for service events
                evdata = self.parse_event_data(root, ns) if event_id in {'7036', '7045'} else None

                # Route to handler
                details = self._dispatch(event_id, ud_elem, ns, evdata)

                writer.writerow([
                    timestamp,
                    'Logged',
                    hostname or '-',
                    '-',
                    self.DESC_MAP[event_id],
                    details,
                    '-',
                    self.evtx_path.split('\\')[-1]
                ])

    def _dispatch(self, event_id, ud_elem, ns, evdata):
        """
        Dispatch event to specific handler based on event_id.
        Returns details string.
        """
        if event_id == '104':
            return self._handle_104(ud_elem, ns)
        if event_id == '7036':
            return self._handle_7036(evdata)
        if event_id == '7045':
            return self._handle_7045(evdata)
        return '-'

    def _handle_104(self, ud_elem, ns):
        """
        Handle EventLog cleared (104).
        """
        subject_user   = self.safe_find_text(ud_elem, 'ud:SubjectUserName', ns)
        subject_domain = self.safe_find_text(ud_elem, 'ud:SubjectDomainName', ns)
        channel        = self.safe_find_text(ud_elem, 'ud:Channel', ns)
        client_pid     = self.safe_find_text(ud_elem, 'ud:ClientProcessId', ns)
        client_key     = self.safe_find_text(ud_elem, 'ud:ClientProcessStartKey', ns)
        return (
            f"EventLog cleared by {subject_domain}\\{subject_user}, "
            f"Channel: {channel}, ProcessId: {client_pid}"
        )

    def _handle_7036(self, evdata):
        """
        Handle service state change (7036).
        """
        svc  = evdata.get('param1', '-')
        stat = evdata.get('param2', '-')
        return f"Service: {svc}, Status: {stat}"

    def _handle_7045(self, evdata):
        """
        Handle service installed (7045).
        """
        svc          = evdata.get('ServiceName', '-')
        path         = evdata.get('ImagePath', '-')
        service_type = evdata.get('ServiceType', '-')
        start_type   = evdata.get('StartType', '-')
        return (
            f"Service: {svc}, Path: {path}, "
            f"Type: {service_type}, StartType: {start_type}"
        )
