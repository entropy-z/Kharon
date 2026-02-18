#!/usr/bin/env python3
"""
CobaltStrike Malleable C2 Profile Parser for Kharon

Converts CobaltStrike malleable profiles to Kharon JSON format. Based on: https://github.com/InfinityCurveLabs/cobalt-parser/blob/main/cobalt-parser.py

Supported Kharon encoding formats:
    - base64
    - base32
    - base64url
    - hex

Usage:
    python cobalt_to_kharon.py <cobalt_profile.profile> <output.json>
    python cobalt_to_kharon.py <cobalt_profile.profile> <output.json> --hosts 192.168.1.1:443,192.168.1.2:443

Author: Oblivion
"""

import json
import argparse
import re
import sys
from pathlib import Path
from typing import Optional

try:
    import malleable
    HAS_MALLEABLE = True
except ImportError:
    HAS_MALLEABLE = False
    print("[!] Warning: 'malleable' module not found. Using basic parser.")

# Kharon supported encoding formats
KHARON_SUPPORTED_FORMATS = ['base64', 'base32', 'base64url', 'hex']

# CobaltStrike to Kharon format mapping
CS_TO_KHARON_FORMAT = {
    'base64': 'base64',
    'base64url': 'base64url',
    # Unsupported formats - will warn and fallback to base64
    'netbios': None,
    'netbiosu': None,
}


class CobaltStrikeParser:
    """Basic CobaltStrike profile parser (fallback when malleable module unavailable)"""
    
    def __init__(self, profile_path: str):
        self.profile_path = profile_path
        self.content = ""
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.http_get = {}
        self.http_post = {}
        self.warnings = []
        
    def parse(self) -> bool:
        """Parse the CobaltStrike profile file"""
        try:
            with open(self.profile_path, 'r') as f:
                self.content = f.read()
            
            # Remove comments
            self.content = re.sub(r'#.*$', '', self.content, flags=re.MULTILINE)
            self.content = re.sub(r'/\*.*?\*/', '', self.content, flags=re.DOTALL)
            
            # Parse user-agent
            ua_match = re.search(r'set\s+useragent\s+"([^"]+)"', self.content)
            if ua_match:
                self.user_agent = ua_match.group(1)
            
            # Parse http-get block
            self.http_get = self._parse_http_block('http-get')
            
            # Parse http-post block
            self.http_post = self._parse_http_block('http-post')
            
            return True
        except Exception as e:
            print(f"[!] Error parsing profile: {e}")
            return False
    
    def _parse_http_block(self, block_name: str) -> dict:
        """Parse an http-get or http-post block"""
        result = {
            'uri': [],
            'client': {
                'headers': {},
                'metadata': {'transforms': [], 'terminator': None},
                'output': {'transforms': [], 'terminator': None},
                'id': {'transforms': [], 'terminator': None}
            },
            'server': {
                'headers': {},
                'output': {'transforms': [], 'terminator': None}
            }
        }
        
        # Find block content
        pattern = rf'{block_name}\s*\{{([^}}]*(?:\{{[^}}]*\}}[^}}]*)*)\}}'
        match = re.search(pattern, self.content, re.DOTALL)
        
        if not match:
            return result
        
        block_content = match.group(1)
        
        # Parse URIs
        uri_match = re.search(r'set\s+uri\s+"([^"]+)"', block_content)
        if uri_match:
            result['uri'] = [u.strip() for u in uri_match.group(1).split()]
        
        # Parse client block
        client_match = re.search(r'client\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}', block_content, re.DOTALL)
        if client_match:
            client_content = client_match.group(1)
            result['client']['headers'] = self._parse_headers(client_content)
            result['client']['metadata'] = self._parse_transform_block(client_content, 'metadata')
            result['client']['output'] = self._parse_transform_block(client_content, 'output')
            result['client']['id'] = self._parse_transform_block(client_content, 'id')
        
        # Parse server block
        server_match = re.search(r'server\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}', block_content, re.DOTALL)
        if server_match:
            server_content = server_match.group(1)
            result['server']['headers'] = self._parse_headers(server_content)
            result['server']['output'] = self._parse_transform_block(server_content, 'output')
        
        return result
    
    def _parse_headers(self, content: str) -> dict:
        """Parse header definitions"""
        headers = {}
        for match in re.finditer(r'header\s+"([^"]+)"\s+"([^"]+)"', content):
            headers[match.group(1)] = match.group(2)
        return headers
    
    def _parse_transform_block(self, content: str, block_name: str) -> dict:
        """Parse a transform block (metadata, output, id)"""
        result = {'transforms': [], 'terminator': None}
        
        pattern = rf'{block_name}\s*\{{([^}}]*)\}}'
        match = re.search(pattern, content, re.DOTALL)
        
        if not match:
            return result
        
        block_content = match.group(1)
        
        # Parse transforms in order (only Kharon-supported ones)
        transform_patterns = [
            (r'base64;', 'base64'),
            (r'base64url;', 'base64url'),
            (r'mask;', 'mask'),
            (r'netbios;', 'netbios'),      # Will be flagged as unsupported
            (r'netbiosu;', 'netbiosu'),    # Will be flagged as unsupported
            (r'prepend\s+"([^"]+)"', 'prepend'),
            (r'append\s+"([^"]+)"', 'append'),
        ]
        
        # Find all transforms with their positions
        transforms_found = []
        for pattern, transform_type in transform_patterns:
            for m in re.finditer(pattern, block_content):
                if transform_type in ['prepend', 'append']:
                    transforms_found.append((m.start(), transform_type, m.group(1)))
                else:
                    transforms_found.append((m.start(), transform_type, None))
        
        # Sort by position
        transforms_found.sort(key=lambda x: x[0])
        result['transforms'] = [(t[1], t[2]) for t in transforms_found]
        
        # Parse terminator
        terminator_patterns = [
            (r'print;', 'print', None),
            (r'header\s+"([^"]+)"', 'header'),
            (r'parameter\s+"([^"]+)"', 'parameter'),
            (r'uri-append;', 'uri-append', None),
        ]
        
        for pattern, term_type, *_ in terminator_patterns:
            m = re.search(pattern, block_content)
            if m:
                if term_type in ['header', 'parameter']:
                    result['terminator'] = (term_type, m.group(1))
                else:
                    result['terminator'] = (term_type, None)
                break
        
        return result


class KharonProfileBuilder:
    """Builds Kharon profile JSON from parsed CobaltStrike data"""
    
    def __init__(self, hosts: list[str], user_agent: str):
        self.hosts = hosts
        self.user_agent = user_agent
        self.warnings = []
        
    def build(self, http_get: dict, http_post: dict) -> dict:
        """Build complete Kharon profile"""
        
        callback = {
            "hosts": self.hosts,
            "user_agent": self.user_agent,
            "server_error": self._build_server_error(),
            "get": self._build_method_config(http_get, is_get=True),
            "post": self._build_method_config(http_post, is_get=False)
        }
        
        return {"callbacks": [callback]}
    
    def _build_server_error(self) -> dict:
        """Build default server error configuration"""
        return {
            "http_status": 404,
            "response": "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>",
            "headers": {
                "Content-Type": "text/html; charset=utf-8"
            }
        }
    
    def _build_method_config(self, http_block: dict, is_get: bool) -> dict:
        """Build GET or POST configuration"""
        
        config = {
            "server_headers": self._build_headers(http_block.get('server', {}).get('headers', {})),
            "client_headers": self._build_headers(http_block.get('client', {}).get('headers', {})),
            "empty_response": "",
            "uri": {}
        }
        
        # Build URI configurations
        uris = http_block.get('uri', ['/'])
        if not uris:
            uris = ['/']
        
        # Group all URIs together with same config
        uri_key = ' '.join(uris)
        
        if is_get:
            # GET: client sends metadata, server sends output
            client_transform = http_block.get('client', {}).get('metadata', {})
            server_transform = http_block.get('server', {}).get('output', {})
        else:
            # POST: client sends output (+ id), server sends output
            client_transform = http_block.get('client', {}).get('output', {})
            server_transform = http_block.get('server', {}).get('output', {})
        
        method_name = "GET" if is_get else "POST"
        
        config['uri'][uri_key] = {
            "server_output": self._build_output_config(server_transform, is_server=True, method=method_name),
            "client_output": self._build_output_config(client_transform, is_server=False, method=method_name)
        }
        
        # Add client parameters if present
        client_params = self._extract_parameters(http_block)
        if client_params:
            config['uri'][uri_key]['client_parameters'] = client_params
        
        return config
    
    def _build_headers(self, headers: dict) -> dict:
        """Build headers dict, filtering out User-Agent"""
        return {k: v for k, v in headers.items() if k.lower() != 'user-agent'}
    
    def _build_output_config(self, transform_data: dict, is_server: bool, method: str) -> dict:
        """Build server_output or client_output configuration"""
        
        transforms = transform_data.get('transforms', [])
        terminator = transform_data.get('terminator')
        
        config = {
            "mask": False,
            "format": "base64"  # Default format
        }
        
        prepend_parts = []
        append_parts = []
        
        output_type = "server_output" if is_server else "client_output"
        
        # Process transforms
        for transform in transforms:
            if isinstance(transform, tuple):
                transform_type, transform_arg = transform
            else:
                transform_type = transform
                transform_arg = None
            
            if transform_type == 'mask':
                config['mask'] = True
            elif transform_type == 'base64':
                config['format'] = 'base64'
            elif transform_type == 'base64url':
                config['format'] = 'base64url'
            elif transform_type in ['netbios', 'netbiosu']:
                # Unsupported - warn and fallback to base64
                warning = f"[!] {method} {output_type}: '{transform_type}' encoding not supported by Kharon. Falling back to 'base64'."
                self.warnings.append(warning)
                config['format'] = 'base64'
            elif transform_type == 'prepend' and transform_arg:
                prepend_parts.append(self._unescape_string(transform_arg))
            elif transform_type == 'append' and transform_arg:
                append_parts.append(self._unescape_string(transform_arg))
        
        # Add prepend/append if present
        if prepend_parts:
            config['prepend'] = ''.join(prepend_parts)
        if append_parts:
            config['append'] = ''.join(append_parts)
        
        # Process terminator
        if terminator:
            term_type, term_arg = terminator
            if term_type == 'header' and term_arg:
                config['header'] = term_arg
            elif term_type == 'parameter' and term_arg:
                config['parameter'] = term_arg
            elif term_type == 'uri-append':
                # Unsupported in Kharon
                warning = f"[!] {method} {output_type}: 'uri-append' terminator not supported by Kharon. Data will be sent in body."
                self.warnings.append(warning)
            # 'print' uses default body output (no action needed)
        
        return config
    
    def _extract_parameters(self, http_block: dict) -> list[dict]:
        """Extract any static parameters from the profile"""
        return []
    
    def _unescape_string(self, s: str) -> str:
        """Unescape CobaltStrike string literals"""
        # Handle hex escapes like \x90
        result = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)
        # Handle common escapes
        result = result.replace('\\n', '\n')
        result = result.replace('\\r', '\r')
        result = result.replace('\\t', '\t')
        result = result.replace('\\"', '"')
        result = result.replace('\\\\', '\\')
        return result


class MalleableProfileAdapter:
    """Adapter for the malleable module (when available)"""
    
    def __init__(self, profile_path: str):
        self.profile_path = profile_path
        self.profile = malleable.Profile()
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.warnings = []
        
    def parse(self) -> bool:
        """Parse using malleable module"""
        try:
            self.profile.ingest(self.profile_path)
            if not self.profile.validate():
                print("[!] Profile validation failed")
                return False
            self.user_agent = self.profile.useragent or self.user_agent
            return True
        except Exception as e:
            print(f"[!] Error parsing profile with malleable: {e}")
            return False
    
    def get_serialized(self) -> dict:
        """Get serialized profile data"""
        return self.profile._serialize()
    
    def build_kharon_profile(self, hosts: list[str]) -> dict:
        """Build Kharon profile from malleable data"""
        
        cs_data = self.get_serialized()
        
        callback = {
            "hosts": hosts,
            "user_agent": self.user_agent,
            "server_error": {
                "http_status": 404,
                "response": "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>",
                "headers": {"Content-Type": "text/html; charset=utf-8"}
            },
            "get": self._build_method('get', cs_data),
            "post": self._build_method('post', cs_data)
        }
        
        return {"callbacks": [callback]}
    
    def _build_method(self, method: str, cs_data: dict) -> dict:
        """Build GET or POST method configuration"""
        
        method_data = cs_data.get(method, {})
        
        config = {
            "server_headers": self._extract_headers(method_data, 'server'),
            "client_headers": self._extract_headers(method_data, 'client'),
            "empty_response": "",
            "uri": {}
        }
        
        # Get URIs
        uris = self._extract_uris(method_data)
        uri_key = ' '.join(uris) if uris else '/'
        
        # Build transforms
        if method == 'get':
            client_transforms = method_data.get('client', {}).get('metadata', {})
            server_transforms = method_data.get('server', {}).get('output', {})
        else:
            client_transforms = method_data.get('client', {}).get('output', {})
            server_transforms = method_data.get('server', {}).get('output', {})
        
        method_upper = method.upper()
        
        config['uri'][uri_key] = {
            "server_output": self._build_output(server_transforms, f"{method_upper} server_output"),
            "client_output": self._build_output(client_transforms, f"{method_upper} client_output")
        }
        
        return config
    
    def _extract_headers(self, method_data: dict, section: str) -> dict:
        """Extract headers from method data"""
        headers = {}
        if section in method_data and 'headers' in method_data[section]:
            for k, v in method_data[section]['headers'].items():
                if k.lower() != 'user-agent':
                    headers[k] = v
        return headers
    
    def _extract_uris(self, method_data: dict) -> list[str]:
        """Extract URIs from method data"""
        uris = []
        if 'client' in method_data and 'uris' in method_data['client']:
            uris = method_data['client']['uris']
        return uris if uris else ['/']
    
    def _build_output(self, transform_data: dict, context: str) -> dict:
        """Build output configuration from transform data"""
        
        config = {
            "mask": False,
            "format": "base64"
        }
        
        prepend_parts = []
        append_parts = []
        
        if 'transforms' in transform_data:
            for action in transform_data['transforms']:
                action_type = action.get('type')
                action_arg = action.get('arg', '')
                
                # Handle hex escape sequences
                if isinstance(action_arg, str) and re.fullmatch(r'(x[0-9a-fA-F]{2})+', action_arg):
                    action_arg = re.sub(r'x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), action_arg)
                
                if action_type == malleable.Transform.MASK:
                    config['mask'] = True
                elif action_type == malleable.Transform.BASE64:
                    config['format'] = 'base64'
                elif action_type == malleable.Transform.BASE64URL:
                    config['format'] = 'base64url'
                elif action_type == malleable.Transform.NETBIOS:
                    warning = f"[!] {context}: 'netbios' encoding not supported by Kharon. Falling back to 'base64'."
                    self.warnings.append(warning)
                    config['format'] = 'base64'
                elif action_type == malleable.Transform.NETBIOSU:
                    warning = f"[!] {context}: 'netbiosu' encoding not supported by Kharon. Falling back to 'base64'."
                    self.warnings.append(warning)
                    config['format'] = 'base64'
                elif action_type == malleable.Transform.PREPEND:
                    prepend_parts.append(action_arg)
                elif action_type == malleable.Transform.APPEND:
                    append_parts.append(action_arg)
        
        if prepend_parts:
            config['prepend'] = ''.join(prepend_parts)
        if append_parts:
            config['append'] = ''.join(append_parts)
        
        # Handle terminator
        if 'terminator' in transform_data:
            term = transform_data['terminator']
            term_type = term.get('type')
            term_arg = term.get('arg', '')
            
            if term_type == malleable.Terminator.HEADER:
                config['header'] = term_arg
            elif term_type == malleable.Terminator.PARAMETER:
                config['parameter'] = term_arg
            elif term_type == malleable.Terminator.URIAPPEND:
                warning = f"[!] {context}: 'uri-append' terminator not supported by Kharon. Data will be sent in body."
                self.warnings.append(warning)
            # PRINT is default (body output)
        
        return config


def parse_hosts(hosts_str: str) -> list[str]:
    """Parse comma-separated hosts string"""
    if not hosts_str:
        return ["127.0.0.1:443"]
    return [h.strip() for h in hosts_str.split(',') if h.strip()]


def print_compatibility_info():
    """Print Kharon compatibility information"""
    print("\n" + "="*60)
    print("KHARON MALLEABLE PROFILE COMPATIBILITY")
    print("="*60)
    print("\nSupported encoding formats:")
    print("  ✓ base64")
    print("  ✓ base32")
    print("  ✓ base64url")
    print("  ✓ hex")
    print("\nSupported transforms:")
    print("  ✓ mask (XOR encryption)")
    print("  ✓ prepend")
    print("  ✓ append")
    print("\nSupported terminators:")
    print("  ✓ print (body - default)")
    print("  ✓ header")
    print("  ✓ parameter")
    print("\nNOT supported (will fallback to base64):")
    print("  ✗ netbios")
    print("  ✗ netbiosu")
    print("  ✗ uri-append")
    print("="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='Convert CobaltStrike Malleable C2 profiles to Kharon JSON format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s profile.profile output.json
    %(prog)s profile.profile output.json --hosts 192.168.1.1:443,192.168.1.2:8443
    %(prog)s profile.profile output.json --hosts c2.example.com:443 --pretty
    %(prog)s --compatibility
    
Supported Kharon formats: base64, base32, base64url, hex
        """
    )
    
    parser.add_argument('COBALT', nargs='?', help='CobaltStrike malleable profile file (.profile)')
    parser.add_argument('OUTPUT', nargs='?', help='Output Kharon JSON profile file')
    parser.add_argument('--hosts', '-H', 
                        help='Comma-separated list of host:port (default: 127.0.0.1:443)',
                        default='127.0.0.1:443')
    parser.add_argument('--pretty', '-p', 
                        action='store_true',
                        help='Pretty print JSON output')
    parser.add_argument('--force-basic', '-f',
                        action='store_true',
                        help='Force use of basic parser instead of malleable module')
    parser.add_argument('--compatibility', '-c',
                        action='store_true',
                        help='Show Kharon compatibility information')
    
    args = parser.parse_args()
    
    # Show compatibility info
    if args.compatibility:
        print_compatibility_info()
        sys.exit(0)
    
    # Validate required arguments
    if not args.COBALT or not args.OUTPUT:
        parser.print_help()
        sys.exit(1)
    
    # Validate input file
    if not Path(args.COBALT).exists():
        print(f"[!] Error: Input file not found: {args.COBALT}")
        sys.exit(1)
    
    # Parse hosts
    hosts = parse_hosts(args.hosts)
    print(f"[*] Target hosts: {hosts}")
    
    # Parse profile
    kharon_profile = None
    all_warnings = []
    
    if HAS_MALLEABLE and not args.force_basic:
        print(f"[*] Parsing with malleable module: {args.COBALT}")
        adapter = MalleableProfileAdapter(args.COBALT)
        if adapter.parse():
            kharon_profile = adapter.build_kharon_profile(hosts)
            all_warnings = adapter.warnings
            print("[+] Successfully parsed with malleable module")
        else:
            print("[!] Malleable parsing failed, falling back to basic parser")
    
    if kharon_profile is None:
        print(f"[*] Parsing with basic parser: {args.COBALT}")
        parser_obj = CobaltStrikeParser(args.COBALT)
        if not parser_obj.parse():
            print("[!] Error: Failed to parse profile")
            sys.exit(1)
        
        builder = KharonProfileBuilder(hosts, parser_obj.user_agent)
        kharon_profile = builder.build(parser_obj.http_get, parser_obj.http_post)
        all_warnings = builder.warnings
        print("[+] Successfully parsed with basic parser")
    
    # Print warnings
    if all_warnings:
        print("\n[!] Compatibility Warnings:")
        for warning in all_warnings:
            print(f"    {warning}")
        print()
    
    # Write output
    try:
        with open(args.OUTPUT, 'w') as f:
            if args.pretty:
                json.dump(kharon_profile, f, indent=4, ensure_ascii=False)
            else:
                json.dump(kharon_profile, f, ensure_ascii=False)
        
        print(f"[+] Kharon profile written to: {args.OUTPUT}")
    except Exception as e:
        print(f"[!] Error writing output: {e}")
        sys.exit(1)
    
    # Print summary
    print("\n[*] Profile Summary:")
    print(f"    Hosts: {len(hosts)}")
    print(f"    User-Agent: {kharon_profile['callbacks'][0]['user_agent'][:60]}...")
    
    for method in ['get', 'post']:
        method_config = kharon_profile['callbacks'][0].get(method, {})
        uris = list(method_config.get('uri', {}).keys())
        print(f"    {method.upper()} URIs: {uris}")
        
        for uri_key, uri_config in method_config.get('uri', {}).items():
            server_out = uri_config.get('server_output', {})
            client_out = uri_config.get('client_output', {})
            print(f"      server_output: format={server_out.get('format', 'base64')}, mask={server_out.get('mask', False)}")
            print(f"      client_output: format={client_out.get('format', 'base64')}, mask={client_out.get('mask', False)}")


if __name__ == "__main__":
    main()