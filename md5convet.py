#!/usr/bin/env python3
"""
MD5 to SHA-256 Converter using VirusTotal API
Processes CSV file containing MD5 hashes and outputs SHA-256 equivalents
"""

import csv
import time
import argparse
import sys
from pathlib import Path
import requests
from typing import Optional, Dict, List, Tuple


class VirusTotalConverter:
    def __init__(self, api_key: str, rate_limit_delay: float = 15.0):
        """
        Initialize VirusTotal API client
        
        Args:
            api_key: VirusTotal API key
            rate_limit_delay: Seconds between requests (default 15 for free tier)
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/files"
        self.headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        self.rate_limit_delay = rate_limit_delay
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Lookup a hash on VirusTotal
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash
            
        Returns:
            Dictionary with file info or None if not found
        """
        url = f"{self.base_url}/{file_hash}"
        
        try:
            response = self.session.get(url)
            
            if response.status_code == 404:
                print(f"  [NOT FOUND] Hash not in VirusTotal database: {file_hash}")
                return None
            
            if response.status_code == 429:
                print(f"  [RATE LIMIT] Hit rate limit, waiting longer...")
                time.sleep(60)  # Extra wait for rate limit
                return self.lookup_hash(file_hash)  # Retry
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"  [ERROR] API request failed: {e}")
            return None
    
    def extract_sha256(self, data: Dict, expected_md5: str) -> Optional[str]:
        """
        Extract SHA-256 from VT response and verify MD5 matches
        
        Args:
            data: VirusTotal API response data
            expected_md5: Original MD5 to verify against
            
        Returns:
            SHA-256 hash if verified, None otherwise
        """
        try:
            attributes = data.get('data', {}).get('attributes', {})
            
            # Get hashes from response
            md5_from_vt = attributes.get('md5', '').lower()
            sha256_from_vt = attributes.get('sha256', '').lower()
            
            # Double-check: Verify MD5 matches what we searched for
            if not md5_from_vt:
                print(f"  [ERROR] No MD5 in VT response")
                return None
            
            if md5_from_vt != expected_md5.lower():
                print(f"  [MISMATCH] VT MD5 ({md5_from_vt}) != Expected ({expected_md5})")
                return None
            
            if not sha256_from_vt:
                print(f"  [ERROR] No SHA-256 in VT response")
                return None
            
            print(f"  [SUCCESS] MD5 verified, SHA-256: {sha256_from_vt}")
            return sha256_from_vt
            
        except Exception as e:
            print(f"  [ERROR] Failed to parse response: {e}")
            return None


def process_csv(
    input_file: str,
    output_file: str,
    api_key: str,
    md5_column: str = 'md5',
    rate_limit: float = 15.0,
    resume: bool = False
) -> Tuple[int, int, int]:
    """
    Process CSV file and convert MD5 to SHA-256
    
    Args:
        input_file: Path to input CSV
        output_file: Path to output CSV
        api_key: VirusTotal API key
        md5_column: Name of column containing MD5 hashes
        rate_limit: Seconds between API requests
        resume: Whether to resume from existing output (skip already processed)
        
    Returns:
        Tuple of (total_processed, successful, failed)
    """
    vt = VirusTotalConverter(api_key, rate_limit)
    
    # Track processed hashes to avoid duplicates and enable resume
    processed_hashes = set()
    
    # Check if output exists for resume mode
    output_path = Path(output_file)
    if resume and output_path.exists():
        print(f"[INFO] Resuming from existing output: {output_file}")
        with open(output_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'md5' in row:
                    processed_hashes.add(row['md5'].lower())
        print(f"[INFO] Found {len(processed_hashes)} already processed hashes")
    
    # Read input CSV
    print(f"[INFO] Reading input file: {input_file}")
    rows_to_process = []
    
    with open(input_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        
        if md5_column not in fieldnames:
            print(f"[ERROR] Column '{md5_column}' not found in CSV. Available: {fieldnames}")
            sys.exit(1)
        
        for row in reader:
            md5 = row.get(md5_column, '').strip().lower()
            # Validate MD5 format (32 hex chars)
            if len(md5) == 32 and all(c in '0123456789abcdef' for c in md5):
                if md5 not in processed_hashes:
                    rows_to_process.append((md5, row))
                else:
                    print(f"[SKIP] Already processed: {md5}")
            else:
                print(f"[SKIP] Invalid MD5 format: {md5}")
    
    total = len(rows_to_process)
    print(f"[INFO] Total hashes to process: {total}")
    print(f"[INFO] Estimated time: ~{total * rate_limit / 60:.1f} minutes")
    print(f"[INFO] Rate limit: {rate_limit}s between requests\n")
    
    # Prepare output
    output_fieldnames = fieldnames + ['sha256', 'vt_found', 'conversion_status']
    
    # Open output file in append mode if resuming, write mode otherwise
    mode = 'a' if resume and output_path.exists() else 'w'
    write_header = not (resume and output_path.exists())
    
    successful = 0
    failed = 0
    
    with open(output_file, mode, newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=output_fieldnames)
        if write_header:
            writer.writeheader()
        
        for idx, (md5, original_row) in enumerate(rows_to_process, 1):
            print(f"[{idx}/{total}] Processing: {md5}")
            
            # Query VirusTotal
            vt_data = vt.lookup_hash(md5)
            
            result_row = original_row.copy()
            
            if vt_data:
                # Double-check and extract SHA-256
                sha256 = vt.extract_sha256(vt_data, md5)
                
                if sha256:
                    result_row['sha256'] = sha256
                    result_row['vt_found'] = 'yes'
                    result_row['conversion_status'] = 'success'
                    successful += 1
                else:
                    result_row['sha256'] = ''
                    result_row['vt_found'] = 'yes'
                    result_row['conversion_status'] = 'hash_mismatch_or_missing'
                    failed += 1
            else:
                result_row['sha256'] = ''
                result_row['vt_found'] = 'no'
                result_row['conversion_status'] = 'not_found'
                failed += 1
            
            writer.writerow(result_row)
            f.flush()  # Ensure write to disk
            
            # Rate limiting (except for last item)
            if idx < total:
                time.sleep(rate_limit)
    
    print(f"\n[INFO] Complete! Total: {total}, Successful: {successful}, Failed: {failed}")
    return total, successful, failed


def main():
    parser = argparse.ArgumentParser(
        description='Convert MD5 hashes to SHA-256 using VirusTotal API'
    )
    parser.add_argument('input_csv', help='Input CSV file with MD5 hashes')
    parser.add_argument('output_csv', help='Output CSV file path')
    parser.add_argument('--api-key', required=True, help='VirusTotal API key')
    parser.add_argument('--md5-column', default='md5', 
                       help='Column name containing MD5 (default: md5)')
    parser.add_argument('--rate-limit', type=float, default=15.0,
                       help='Seconds between requests (default: 15 for free tier)')
    parser.add_argument('--resume', action='store_true',
                       help='Resume from existing output file')
    
    args = parser.parse_args()
    
    # Validate input file exists
    if not Path(args.input_csv).exists():
        print(f"[ERROR] Input file not found: {args.input_csv}")
        sys.exit(1)
    
    # Run conversion
    process_csv(
        input_file=args.input_csv,
        output_file=args.output_csv,
        api_key=args.api_key,
        md5_column=args.md5_column,
        rate_limit=args.rate_limit,
        resume=args.resume
    )


if __name__ == "__main__":
    main()