import argparse
import os
import sys
from Modules.LocalSessionManager import TerminalServicesLSMParser
from Modules.RDPClient import TerminalServicesCAXParser
from Modules.PowerShell import PowerShellParser
from Modules.System import SystemParser
from Modules.Security import SecurityParser
from Modules.WinRM import WinRMParser

# Mapping parser types to classes
PARSERS = {
    'ts_lsm': TerminalServicesLSMParser,
    'ts_rdp': TerminalServicesCAXParser,
    'powershell': PowerShellParser,
    'system': SystemParser,
    'security': SecurityParser,
    'winrm': WinRMParser
}

# File name patterns to detect appropriate parser
FILE_PATTERNS = {
    'ts_lsm': 'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx',
    'ts_rdp': 'Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx',
    'powershell': 'Windows PowerShell.evtx',
    'system': 'System.evtx',
    'security': 'Security.evtx',
    'winrm': 'Microsoft-Windows-WinRM%4Operational.evtx'
}

# Custom ArgumentParser to print help on error
class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.exit(2)

def main():
    parser = CustomArgumentParser(
        description='DFIR EventLog Parser',
        epilog="""
Available parser types:
  ts_lsm      Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
  ts_cax      Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx
  powershell  Windows PowerShell.evtx
  system      System.evtx
  security    Security.evtx
  winrm       Microsoft-Windows-WinRM%4Operational.evtx'
""",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Short options added for convenience
    parser.add_argument('-t', '--type',    required=True,
                        choices=list(PARSERS.keys())+['auto'],
                        help='Parser type to use or "auto" for directory scan')
    parser.add_argument('-i', '--input',   help='Path to input EVTX file')
    parser.add_argument('-o', '--output',  help='Path to output CSV file')
    parser.add_argument('-d', '--dir',     help='Directory with EVTX files when using auto')
    args = parser.parse_args()

    if args.type == 'auto':
        if not args.dir:
            parser.error('When type is auto, --dir (-d) must be specified')
        for fname in os.listdir(args.dir):
            if not fname.lower().endswith('.evtx'):
                continue
            evtx_path = os.path.join(args.dir, fname)
            matched = False
            for key, pattern in FILE_PATTERNS.items():
                if pattern.lower() in fname.lower():
                    parser_cls = PARSERS[key]
                    csv_path = os.path.splitext(evtx_path)[0] + '.csv'
                    print(f"[auto] Parsing {fname} with {key} parser...")
                    parser_inst = parser_cls(evtx_path, csv_path)
                    parser_inst.parse()
                    print(f"[auto] Saved CSV: {csv_path}")
                    matched = True
                    break
            if not matched:
                print(f"[auto] Skipping {fname}: no matching parser pattern")
    else:
        # single file mode
        if not args.input or not args.output:
            parser.error('When not auto, both --input and --output must be specified')
        parser_cls = PARSERS[args.type]
        parser_inst = parser_cls(args.input, args.output)
        parser_inst.parse()
        print(f"[{args.type}] Parsing completed. Output saved to: {args.output}")

if __name__ == '__main__':
    main()