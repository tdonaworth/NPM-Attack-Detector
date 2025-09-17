#!/usr/bin/env python3
"""
NPM Supply Chain Attack Detection Script
Detects compromised packages from the September 2025 Qix account compromise

This script detects:
1. Known compromised package versions
2. Obfuscated malicious code patterns
3. Crypto address replacement signatures
4. Network interception patterns
"""

import json
import os
import re
import hashlib
import sys
from pathlib import Path
import subprocess

# Known compromised packages and versions
COMPROMISED_PACKAGES = {
    "backslash": ["0.2.1"],
    "chalk": ["5.6.1"],
    "chalk-template": ["1.1.1"],
    "color-convert": ["3.1.1"],
    "color-name": ["2.0.1"],
    "color-string": ["2.1.1"],
    "wrap-ansi": ["9.0.1"],
    "supports-hyperlinks": ["4.1.1"],
    "strip-ansi": ["7.1.1"],
    "slice-ansi": ["7.1.1"],
    "simple-swizzle": ["0.2.3"],
    "is-arrayish": ["0.3.3"],
    "error-ex": ["1.3.3"],
    "has-ansi": ["6.0.1"],
    "ansi-regex": ["6.2.1"],
    "ansi-styles": ["6.2.2"],
    "supports-color": ["10.2.1"],
    "proto-tinker-wc": ["1.8.7"],
    "debug": ["4.4.2"]
}

# Malicious code signatures (regex patterns)
MALICIOUS_SIGNATURES = [
    # Obfuscated variable patterns
    r'_0x[a-f0-9]{4,6}',

    # Crypto address patterns in arrays
    r'0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976',
    r'1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx',
    r'bc1qms4f8ys8c4z47h0q29nnmyekc9r74u5ypqw6wm',

    # Function patterns for crypto replacement
    r'replaceCryptoHashes',
    r'findNearestAddressLevenshtein',
    r'checkethereumw',

    # Network interception patterns
    r'XMLHttpRequest\.prototype\.open\s*=',
    r'XMLHttpRequest\.prototype\.send\s*=',
    r'const\s+originalFetch\s*=\s*fetch',

    # Ethereum detection patterns
    r'window\.ethereum\.request',
    r'eth_accounts',

    # Regex for crypto addresses
    r'\\b0x\[a-fA-F0-9\]\{40\}\\b',
    r'\\b1\[a-km-zA-HJ-NP-Z1-9\]\{25,34\}\\b',
    r'bc1\[qpzry9x8gf2tvdw0s3jn54khce6mua7l\]\{11,71\}',

    # Levenshtein distance implementation
    r'Math\.min\([^)]*_0x[a-f0-9]+\[[^\]]+\]',

    # Content-Type header manipulation
    r'Content-Type.*application/json',

    # Response cloning and manipulation
    r'\.clone\(\)\.json\(\)',
    r'\.clone\(\)\.text\(\)',

    # Specific malicious wallet addresses (sample)
    r'0xa29eeFb3f21Dc8FA8bce065Db4f4354AA683c024',
    r'TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67',
    r'5VVyuV5K6c2gMq1zVeQUFAmo8shPZH28MJCVzccrsZG6'
]

# File extensions to scan
SCAN_EXTENSIONS = ['.js', '.mjs', '.ts', '.jsx', '.tsx']

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 60)
    print("  NPM Supply Chain Attack Detection Tool")
    print("  Detecting September 2025 Qix Account Compromise")
    print("=" * 60)
    print(f"{Colors.END}")

def check_package_json(file_path):
    """Check package.json for compromised dependencies"""
    threats = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check dependencies and devDependencies
        for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
            if dep_type in data:
                for package, version in data[dep_type].items():
                    if package in COMPROMISED_PACKAGES:
                        # Remove version prefixes like ^, ~, >=
                        clean_version = re.sub(r'^[\^~>=<]+', '', version)
                        if clean_version in COMPROMISED_PACKAGES[package]:
                            threats.append({
                                'type': 'compromised_package',
                                'package': package,
                                'version': version,
                                'file': file_path,
                                'severity': 'CRITICAL'
                            })
    except (json.JSONDecodeError, FileNotFoundError, UnicodeDecodeError):
        pass

    return threats

def check_package_lock(file_path):
    """Check package-lock.json for compromised packages"""
    threats = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check packages in lockfile
        if 'packages' in data:
            for package_path, package_info in data['packages'].items():
                if package_path.startswith('node_modules/'):
                    package_name = package_path.replace('node_modules/', '').split('/')[0]
                    if package_name in COMPROMISED_PACKAGES:
                        version = package_info.get('version', '')
                        if version in COMPROMISED_PACKAGES[package_name]:
                            threats.append({
                                'type': 'compromised_package_lock',
                                'package': package_name,
                                'version': version,
                                'file': file_path,
                                'severity': 'CRITICAL'
                            })

        # Also check legacy dependencies format
        if 'dependencies' in data:
            for package, info in data['dependencies'].items():
                if package in COMPROMISED_PACKAGES:
                    version = info.get('version', '')
                    if version in COMPROMISED_PACKAGES[package]:
                        threats.append({
                            'type': 'compromised_package_lock_legacy',
                            'package': package,
                            'version': version,
                            'file': file_path,
                            'severity': 'CRITICAL'
                        })
    except (json.JSONDecodeError, FileNotFoundError, UnicodeDecodeError):
        pass

    return threats

def scan_file_content(file_path):
    """Scan file content for malicious patterns"""
    threats = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Check for malicious signatures
        for i, pattern in enumerate(MALICIOUS_SIGNATURES):
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                threats.append({
                    'type': 'malicious_pattern',
                    'pattern_id': i,
                    'pattern': pattern,
                    'matches': len(matches),
                    'file': file_path,
                    'severity': 'HIGH' if i < 10 else 'MEDIUM'
                })

        # Check for suspicious obfuscation (high density of _0x variables)
        obfuscated_vars = re.findall(r'_0x[a-f0-9]{4,6}', content)
        if len(obfuscated_vars) > 20:  # Threshold for suspicion
            threats.append({
                'type': 'heavy_obfuscation',
                'obfuscated_vars': len(obfuscated_vars),
                'file': file_path,
                'severity': 'HIGH'
            })

        # Check for crypto address arrays (multiple addresses in arrays)
        crypto_addresses = re.findall(
            r'["\']((?:0x[a-fA-F0-9]{40}'  # Ethereum
            r'|1[a-km-zA-HJ-NP-Z1-9]{25,34}'  # Bitcoin legacy
            r'|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,71}'  # Bitcoin bech32
            r'|T[1-9A-HJ-NP-Za-km-z]{33}))["\']',  # Tron
            content)
        if len(crypto_addresses) > 10:  # Multiple crypto addresses suggest malicious intent
            threats.append({
                'type': 'crypto_address_array',
                'address_count': len(crypto_addresses),
                'file': file_path,
                'severity': 'HIGH'
            })

    except (UnicodeDecodeError, FileNotFoundError):
        pass

    return threats

def scan_directory(directory):
    """Recursively scan directory for threats"""
    all_threats = []
    directory = Path(directory)

    print(f"{Colors.BLUE}Scanning directory: {directory}{Colors.END}")

    # Scan package.json files
    for package_json in directory.rglob('package.json'):
        threats = check_package_json(package_json)
        all_threats.extend(threats)

    # Scan package-lock.json files
    for package_lock in directory.rglob('package-lock.json'):
        threats = check_package_lock(package_lock)
        all_threats.extend(threats)

    # Scan JavaScript/TypeScript files
    for ext in SCAN_EXTENSIONS:
        for file_path in directory.rglob(f'*{ext}'):
            # Skip node_modules for content scanning (too many files)
            if 'node_modules' in str(file_path):
                continue
            threats = scan_file_content(file_path)
            all_threats.extend(threats)

    return all_threats

def print_threat(threat):
    """Print a threat with appropriate formatting"""
    severity_colors = {
        'CRITICAL': Colors.RED + Colors.BOLD,
        'HIGH': Colors.RED,
        'MEDIUM': Colors.YELLOW,
        'LOW': Colors.GREEN
    }

    color = severity_colors.get(threat['severity'], Colors.WHITE)
    print(f"{color}[{threat['severity']}]{Colors.END} {threat['type']}")
    print(f"  File: {threat['file']}")

    if threat['type'] in ['compromised_package', 'compromised_package_lock', 'compromised_package_lock_legacy']:
        print(f"  Package: {threat['package']} v{threat['version']}")
    elif threat['type'] == 'malicious_pattern':
        print(f"  Pattern: {threat['pattern']}")
        print(f"  Matches: {threat['matches']}")
    elif threat['type'] == 'heavy_obfuscation':
        print(f"  Obfuscated variables: {threat['obfuscated_vars']}")
    elif threat['type'] == 'crypto_address_array':
        print(f"  Crypto addresses found: {threat['address_count']}")

    print()

def generate_report(threats, output_file=None):
    """Generate a detailed report"""
    report = {
        'scan_timestamp': __import__('datetime').datetime.now().isoformat(),
        'total_threats': len(threats),
        'threats_by_severity': {},
        'threats': threats
    }

    # Count by severity
    for threat in threats:
        severity = threat['severity']
        report['threats_by_severity'][severity] = report['threats_by_severity'].get(severity, 0) + 1

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"{Colors.GREEN}Report saved to: {output_file}{Colors.END}")

    return report

def main():
    print_banner()

    # Get scan directory from command line or use current directory
    scan_dir = sys.argv[1] if len(sys.argv) > 1 else '.'

    if not os.path.exists(scan_dir):
        print(f"{Colors.RED}Error: Directory '{scan_dir}' does not exist{Colors.END}")
        sys.exit(1)

    print(f"Starting scan of: {os.path.abspath(scan_dir)}")
    print()

    # Perform scan
    threats = scan_directory(scan_dir)

    # Print results
    if threats:
        print(f"{Colors.RED}{Colors.BOLD}THREATS DETECTED: {len(threats)}{Colors.END}")
        print()

        # Group and sort threats by severity
        critical_threats = [t for t in threats if t['severity'] == 'CRITICAL']
        high_threats = [t for t in threats if t['severity'] == 'HIGH']
        medium_threats = [t for t in threats if t['severity'] == 'MEDIUM']
        low_threats = [t for t in threats if t['severity'] == 'LOW']

        for threat_group in [critical_threats, high_threats, medium_threats, low_threats]:
            for threat in threat_group:
                print_threat(threat)

        # Generate report
        report_file = f"npm_security_scan_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        generate_report(threats, report_file)

        # Print summary
        print(f"{Colors.BOLD}SUMMARY:{Colors.END}")
        print(f"  Critical: {len(critical_threats)}")
        print(f"  High: {len(high_threats)}")
        print(f"  Medium: {len(medium_threats)}")
        print(f"  Low: {len(low_threats)}")

        if critical_threats or high_threats:
            print(f"{Colors.RED}{Colors.BOLD}")
            print("⚠️  IMMEDIATE ACTION REQUIRED ⚠️")
            print("Critical or high-severity threats detected!")
            print("1. Disconnect affected systems from the internet")
            print("2. Review and remove compromised packages")
            print("3. Check for unauthorized crypto transactions")
            print("4. Update to safe package versions")
            print(f"{Colors.END}")
            sys.exit(1)
    else:
        print(f"{Colors.GREEN}{Colors.BOLD}✅ No threats detected{Colors.END}")
        print("Your project appears to be clean of known compromised packages.")

    print()
    print("Scan completed.")

if __name__ == "__main__":
    main()
