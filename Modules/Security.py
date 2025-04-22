from Lib.common import BaseParser, ET, csv

class SecurityParser(BaseParser):
    """
    Parser for Windows Security events.
    """
    DESC_MAP = {
        '4624': 'Logon success',
        '4625': 'Logon failure',
        '4634': 'Logoff',
        '4648': 'Explicit logon',
        '1102': 'Security log cleared',
        '4720': 'Account created',
        '4722': 'Account enabled',
        '4724': 'Password reset',
        '4723': 'User changed password',
        '4725': 'Account disabled',
        '4726': 'Account deleted',
        '4781': 'Account renamed',
        '4738': 'User account changed',
        '4688': 'Process created',
        '4732': 'Account added to group',
        '4733': 'Account removed from a group'
    }
    ALLOWED = {'3', '7', '10'}

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

                # Override 'ud' namespace dynamically
                ud_parent = root.find('.//ev:UserData', ns)
                ud_elem = next(iter(ud_parent), None) if ud_parent is not None else None
                ns['ud'] = ud_elem.tag[1:].split('}')[0] if ud_elem is not None and ud_elem.tag.startswith('{') else ''

                # Extract Event ID
                eid = self.safe_find_text(root, './/ev:System/ev:EventID', ns)
                if eid not in self.DESC_MAP:
                    continue

                timestamp = self.parse_timestamp(root, ns)
                hostname = self.safe_find_text(root, './/ev:System/ev:Computer', ns)

                # Parse EventData for non-1102 events
                evdata = {} if eid == '1102' else self.parse_event_data(root, ns)

                # Dispatch to handler
                if eid == '1102':
                    details, evdata_str, extip = self._handle_1102(ud_elem, ns)
                elif eid in {'4624', '4625', '4634', '4648'}:
                    details, evdata_str, extip = self._handle_logon(evdata)
                    if details is None:
                        continue
                elif eid in {'4732', '4733'}:
                    details, evdata_str, extip = self._handle_group(evdata)
                elif eid in {'4720', '4722', '4723', '4724', '4725', '4726', '4738', '4781'}:
                    details, evdata_str, extip = self._handle_account_events(evdata)
                else:
                    # Process Created (4688) or other events
                    details = evdata.get('ProcessName', '-') if eid == '4688' else '-'
                    evdata_str = '-' #'; '.join(f"{k}={v}" for k, v in evdata.items()) or '-'
                    extip = '-'

                writer.writerow([
                    timestamp,
                    'Logged',
                    hostname or '-',
                    extip,
                    self.DESC_MAP[eid],
                    details,
                    evdata_str,
                    self.evtx_path.split('\\')[-1]
                ])

    def _handle_1102(self, ud_elem, ns):
        """
        Handle Security log cleared event (1102).
        """
        subject_name   = self.safe_find_text(ud_elem, 'ud:SubjectUserName', ns)
        subject_domain = self.safe_find_text(ud_elem, 'ud:SubjectDomainName', ns)
        client_pid     = self.safe_find_text(ud_elem, 'ud:ClientProcessId', ns)

        details = f"User: {subject_domain}\\{subject_name}, ProcessId: {client_pid}"
        return details, '-', '-'

    def _handle_logon(self, evdata):
        """
        Handle logon/logoff/explicit logon events.
        """
        lt = evdata.get('LogonType', '')
        if lt not in self.ALLOWED:
            return None, None, None

        user     = evdata.get('TargetUserName', '-')
        logon_id = evdata.get('TargetLogonId', '-')
        ip       = evdata.get('IpAddress', '-')
        port     = evdata.get('IpPort', '-')
        process  = evdata.get('ProcessName', '-')
        extip    = ip if self.is_public_ip(ip) else '-'

        details = (
            f"User: {user}, LogonType: {lt}, "
            f"Address: {ip}:{port}, LogonID: {logon_id}, Process: {process}"
        )
        evdata_str = '-' #'; '.join(f"{k}={v}" for k, v in evdata.items()) or '-'
        return details, evdata_str, extip

    def _handle_group(self, evdata):
        # reuse common account_events to get base details and evdata_str
        base_details, base_evstr, extip = self._handle_account_events(evdata)
        member_name = evdata.get('MemberName', '-')
        member_sid  = evdata.get('MemberSid', '-')
        details = f"{base_details}, MemberName: {member_name}, MemberSid: {member_sid}"
        return details, base_evstr, extip
    
    def _handle_4688(self, evdata):
        processname   = evdata.get('NewProcessName', '-')
        pid = evdata.get('NewProcessId', '-')
        ppid    = evdata.get('ProcessId', '-')
        pprocessname  = evdata.get('ParentProcessName', '-')
        command     = evdata.get('CommandLine','-')
        extip = '-'
        details = (
            f"ProcessName: {processname}, PID: {pid}, CommandLine: {command}"
            f"ParentName: {pprocessname}, ppid: {pid}"
        )
        evdata_str = '-' #'; '.join(f"{k}={v}" for k, v in evdata.items()) or '-'
        return details, evdata_str, extip

    def _handle_account_events(self, evdata):
        subject_name   = evdata.get('SubjectUserName', '-')
        subject_domain = evdata.get('SubjectDomainName', '-')
        target_name    = evdata.get('TargetUserName', '-')
        target_domain  = evdata.get('TargetDomainName', '-')
        target_sid     = evdata.get('TargetSid','-')
        extip = '-'
        details = (
            f"Subject: {subject_domain}\\{subject_name}, "
            f"Target: {target_domain}\\{target_name}, TSID: {target_sid}"
        )
        evdata_str = '-' #'; '.join(f"{k}={v}" for k, v in evdata.items()) or '-'
        return details, evdata_str, extip
