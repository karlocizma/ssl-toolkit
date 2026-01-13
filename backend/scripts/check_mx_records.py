#!/usr/bin/env python3
"""
MX Record Checker Script

This script reads a CSV file containing domain names and performs MX record lookups
for each domain, filtering results to show only domains with MX records pointing to
sf.mehlrelay.de.

Example Usage:
    python check_mx_records.py domains.csv
    python check_mx_records.py path/to/domains.csv --output custom_results.csv

CSV Format:
    The CSV file should contain domain names. The script automatically detects the
    column containing domain names. Supported formats:
    
    1. Single column with domains:
       domain
       example.com
       test.org
    
    2. Multiple columns (domain column auto-detected):
       name,domain,notes
       Site 1,example.com,primary
       Site 2,test.org,backup
    
    3. Headerless CSV (first row is data):
       example.com
       test.org

Requirements:
    - dnspython library (already in project dependencies)
    - CSV file with domain names

Output:
    - Console: Simple list of matching domains
    - CSV file: results.csv with columns: Domain, MX Record, Points to sf.mehlrelay.de
"""

import argparse
import csv
import sys
import io
from typing import List, Dict, Optional
import dns.resolver
import dns.exception


DEFAULT_DNS_TIMEOUT = 5
TARGET_MX_SERVER = 'sf.mehlrelay.de'


def find_domain_column(reader: csv.DictReader, fieldnames: List[str]) -> Optional[str]:
    """
    Find the column that contains domain names.
    
    Args:
        reader: CSV DictReader object
        fieldnames: List of field names from CSV
        
    Returns:
        Name of the column containing domains, or None if not found
    """
    domain_keywords = ['domain', 'domain_name', 'hostname', 'host']
    
    # First, check for exact matches with common domain column names (exclude 'name' to avoid false positives)
    for keyword in domain_keywords:
        if keyword in fieldnames:
            return keyword
    
    # If no exact match, look for partial matches (case-insensitive)
    for field in fieldnames:
        field_lower = field.lower()
        for keyword in domain_keywords:
            if keyword in field_lower:
                return field
    
    # If still not found, check values in first few rows
    row_count = 0
    for row in reader:
        for field, value in row.items():
            if value and '.' in str(value) and not str(value).startswith('http'):
                # Likely a domain
                return field
        row_count += 1
        if row_count >= 5:
            break
    
    # Default to second column if available (often name, domain, ...), otherwise first
    if len(fieldnames) > 1:
        return fieldnames[1]
    return fieldnames[0] if fieldnames else None


def check_mx_records(domain: str, timeout: int = DEFAULT_DNS_TIMEOUT) -> Dict:
    """
    Perform MX record lookup for a domain.
    
    Args:
        domain: Domain name to check
        timeout: DNS query timeout in seconds
        
    Returns:
        Dictionary containing:
        - domain: The domain that was checked
        - mx_records: List of MX records found
        - points_to_target: Boolean indicating if any MX points to sf.mehlrelay.de
        - error: Error message if lookup failed, None otherwise
    """
    result = {
        'domain': domain.strip(),
        'mx_records': [],
        'points_to_target': False,
        'error': None
    }
    
    domain = result['domain']
    
    # Basic domain validation
    if not domain or '.' not in domain:
        result['error'] = 'Invalid domain format'
        return result
    
    # Clean the domain
    domain = domain.lower().strip()
    if domain.startswith('http://') or domain.startswith('https://'):
        domain = domain.split('://')[1].split('/')[0]
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        # Query MX records
        answers = resolver.resolve(domain, 'MX')
        
        mx_records = []
        for rdata in answers:
            preference = rdata.preference
            exchange = str(rdata.exchange).rstrip('.')
            mx_records.append(f'{preference} {exchange}')
            
            # Check if this MX points to our target
            if TARGET_MX_SERVER in exchange.lower():
                result['points_to_target'] = True
        
        result['mx_records'] = mx_records
        
    except dns.resolver.NXDOMAIN:
        result['error'] = 'NXDOMAIN - Domain does not exist'
    except dns.resolver.NoAnswer:
        result['error'] = 'No MX records found'
    except dns.resolver.NoNameservers:
        result['error'] = 'No nameservers available'
    except dns.exception.Timeout:
        result['error'] = 'DNS query timeout'
    except dns.exception.DNSException as e:
        result['error'] = f'DNS error: {str(e)}'
    except Exception as e:
        result['error'] = f'Unexpected error: {str(e)}'
    
    return result


def read_domains_from_csv(csv_path: str) -> List[str]:
    """
    Read domain names from a CSV file.
    
    Args:
        csv_path: Path to the CSV file
        
    Returns:
        List of domain names
        
    Raises:
        FileNotFoundError: If CSV file doesn't exist
        ValueError: If no domains found in CSV
    """
    domains = []
    
    try:
        # Read entire file first to analyze
        with open(csv_path, 'r', newline='', encoding='utf-8') as f:
            lines = f.readlines()
        
        if not lines:
            raise ValueError('CSV file is empty')
        
        first_line = lines[0].strip()
        
        # Common header names for domain detection (exclude 'name' to avoid false positives)
        common_headers = ['domain', 'domain_name', 'hostname', 'host']
        
        # Check for delimiters in first line
        has_comma = ',' in first_line
        has_tab = '\t' in first_line
        has_semicolon = ';' in first_line
        
        # If no delimiters found, it's a single column file
        if not has_comma and not has_tab and not has_semicolon:
            # Single column file - check if first line is a header
            is_header = any(h in first_line.lower() for h in common_headers)
            
            start_idx = 1 if is_header else 0
            for i in range(start_idx, len(lines)):
                domain = lines[i].strip()
                if domain:
                    domains.append(domain)
        else:
            # Multi-column CSV - determine delimiter
            if has_tab:
                delimiter = '\t'
            elif has_semicolon:
                delimiter = ';'
            else:
                delimiter = ','
            
            # Check if first line is a header by checking if any field matches domain headers
            fields = [f.strip().lower() for f in first_line.split(delimiter)]
            is_header = any(field in common_headers for field in fields)
            
            if is_header:
                # Find domain column from header
                sample = '\n'.join(lines[:min(10, len(lines))])
                reader = csv.DictReader(io.StringIO(sample), delimiter=delimiter)
                fieldnames = reader.fieldnames or []
                
                domain_column = find_domain_column(reader, fieldnames)
                
                if domain_column:
                    # Read all rows and extract domain column
                    reader = csv.DictReader(io.StringIO('\n'.join(lines)), delimiter=delimiter)
                    for row in reader:
                        domain = row.get(domain_column, '').strip()
                        if domain:
                            domains.append(domain)
                else:
                    raise ValueError('Could not find domain column in CSV')
            else:
                # No headers, treat all values as domains
                for line in lines:
                    values = line.strip().split(delimiter)
                    for value in values:
                        domain = value.strip()
                        if domain:
                            domains.append(domain)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_domains = []
        for domain in domains:
            if domain not in seen:
                seen.add(domain)
                unique_domains.append(domain)
        
        return unique_domains
            
    except FileNotFoundError:
        raise FileNotFoundError(f'CSV file not found: {csv_path}')
    except Exception as e:
        raise ValueError(f'Error reading CSV file: {str(e)}')


def write_results_csv(results: List[Dict], output_path: str):
    """
    Write results to a CSV file.
    
    Args:
        results: List of result dictionaries from check_mx_records
        output_path: Path to output CSV file
    """
    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Domain', 'MX Record', 'Points to sf.mehlrelay.de', 'Error']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for result in results:
                mx_records_str = '; '.join(result['mx_records']) if result['mx_records'] else 'N/A'
                points_to = 'yes' if result['points_to_target'] else 'no'
                
                writer.writerow({
                    'Domain': result['domain'],
                    'MX Record': mx_records_str,
                    'Points to sf.mehlrelay.de': points_to,
                    'Error': result['error'] or ''
                })
        
        print(f'\nResults written to: {output_path}')
        
    except Exception as e:
        print(f'Error writing results CSV: {str(e)}', file=sys.stderr)


def print_console_summary(results: List[Dict]):
    """
    Print a summary of results to console.
    
    Args:
        results: List of result dictionaries from check_mx_records
    """
    total_domains = len(results)
    matching_domains = [r for r in results if r['points_to_target']]
    errors = [r for r in results if r['error']]
    
    print('\n' + '='*60)
    print('MX RECORD CHECK SUMMARY')
    print('='*60)
    print(f'Total domains checked: {total_domains}')
    print(f'Domains pointing to {TARGET_MX_SERVER}: {len(matching_domains)}')
    print(f'Errors encountered: {len(errors)}')
    print('='*60)
    
    if matching_domains:
        print(f'\nDomains with MX records pointing to {TARGET_MX_SERVER}:')
        print('-'*60)
        for result in matching_domains:
            mx_str = ', '.join(result['mx_records'])
            print(f'  {result["domain"]}')
            print(f'    MX: {mx_str}')
    
    if errors:
        print(f'\nDomains with errors:')
        print('-'*60)
        for result in errors:
            print(f'  {result["domain"]}: {result["error"]}')


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Check MX records for domains and filter those pointing to sf.mehlrelay.de',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s domains.csv
  %(prog)s path/to/domains.csv --output custom_results.csv
  %(prog)s domains.csv --timeout 10
        """
    )
    
    parser.add_argument(
        'csv_file',
        help='Path to CSV file containing domain names'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='results.csv',
        help='Output CSV file path (default: results.csv)'
    )
    
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=DEFAULT_DNS_TIMEOUT,
        help=f'DNS query timeout in seconds (default: {DEFAULT_DNS_TIMEOUT})'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed progress information'
    )
    
    args = parser.parse_args()
    
    # Read domains from CSV
    try:
        print(f'Reading domains from: {args.csv_file}')
        domains = read_domains_from_csv(args.csv_file)
        print(f'Found {len(domains)} unique domains to check\n')
    except Exception as e:
        print(f'Error: {str(e)}', file=sys.stderr)
        sys.exit(1)
    
    if not domains:
        print('Error: No domains found in CSV file', file=sys.stderr)
        sys.exit(1)
    
    # Check MX records for each domain
    results = []
    total_domains = len(domains)
    
    print('Checking MX records...\n')
    
    for i, domain in enumerate(domains, 1):
        if args.verbose:
            print(f'[{i}/{total_domains}] Checking: {domain}...')
        
        result = check_mx_records(domain, args.timeout)
        results.append(result)
        
        # Progress indicator
        if not args.verbose:
            progress = int((i / total_domains) * 50)
            bar = '[' + '='*progress + ' '*(50-progress) + ']'
            print(f'\r{bar} {i}/{total_domains}', end='', flush=True)
        
        if args.verbose:
            status = '✓ MATCH' if result['points_to_target'] else ('✗' if result['error'] else '-')
            print(f'    {status} MX Records: {result["mx_records"] or "None"}')
            if result['error']:
                print(f'    Error: {result["error"]}')
    
    if not args.verbose:
        print()  # New line after progress bar
    
    # Print summary to console
    print_console_summary(results)
    
    # Write results to CSV
    write_results_csv(results, args.output)
    
    print(f'\nDone!')


if __name__ == '__main__':
    main()
