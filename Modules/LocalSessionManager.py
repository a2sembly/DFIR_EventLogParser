from Lib.common import BaseParser, ET, csv

class TerminalServicesLSMParser(BaseParser):
    """
    Parser for TerminalServices-LocalSessionManager events.
    """
    DESC_MAP = {
        '21': 'Session logon succeeded',
        '22': 'Session start notification',
        '23': 'Session logoff',
        '24': 'Session disconnected',
        '25': 'Session reconnection succeeded',
        '39': 'RDP session disconnect by user (39)',
        '40': 'RDP session disconnect by user (40)'
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
                hostname  = self.safe_find_text(root, './/ev:System/ev:Computer', ns)

                ud_parent = root.find('.//ev:UserData', ns)
                if not ud_parent:
                    continue
                ud_elem = next(iter(ud_parent), None)
                if not ud_elem:
                    continue
                ns['ud'] = ud_elem.tag[1:].split('}')[0] if ud_elem.tag.startswith('{') else ''

                # Dispatch to handler
                details, extip = self._dispatch(event_id, ud_elem, ns)

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

    def _dispatch(self, event_id, ud_elem, ns):
        """
        Route to the correct handler based on event_id.
        Returns details string and extip.
        """
        if event_id in {'21','22','23','24','25'}:
            return self._handle_session_events(ud_elem, ns)
        if event_id == '39':
            return self._handle_disconnect_39(ud_elem, ns)
        if event_id == '40':
            return self._handle_disconnect_40(ud_elem, ns)
        return '-', '-'

    def _handle_session_events(self, ud_elem, ns):
        """
        Handle session logon, start, logoff, disconnect, reconnection events (21-25).
        """
        user       = self.safe_find_text(ud_elem, 'ud:User', ns)
        addr       = self.safe_find_text(ud_elem, 'ud:Address', ns)
        session_id = self.safe_find_text(ud_elem, 'ud:SessionID', ns)
        extip      = addr if self.is_public_ip(addr) else '-'
        details    = f"User: {user}, IP: {addr}, Session ID: {session_id}"
        return details, extip

    def _handle_disconnect_39(self, ud_elem, ns):
        """
        Handle RDP session disconnect by user (39).
        """
        session_id = self.safe_find_text(ud_elem, 'ud:TargetSession', ns)
        source_id  = self.safe_find_text(ud_elem, 'ud:Source', ns)
        details    = f"Session {session_id} disconnected by session {source_id}"
        return details, '-'

    def _handle_disconnect_40(self, ud_elem, ns):
        """
        Handle RDP session disconnect (40).
        """
        session_id = self.safe_find_text(ud_elem, 'ud:Session', ns)
        reason     = self.safe_find_text(ud_elem, 'ud:Reason', ns)
        details    = f"Session {session_id} disconnected, reason code {reason}"
        return details, '-'
