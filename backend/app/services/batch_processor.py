from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from app.utils.ssl_utils import get_certificate_info
from app.services.ssl_checker import check_ssl_certificate, check_ocsp_status, check_crl_status


def process_certificates_batch(certificates: List[str], operations: List[str] = None) -> Dict:
    if operations is None:
        operations = ['decode']
    
    results = []
    errors = []
    
    for idx, cert_pem in enumerate(certificates):
        cert_id = f"cert_{idx + 1}"
        cert_result = {
            'id': cert_id,
            'index': idx
        }
        
        try:
            if 'decode' in operations:
                cert_result['certificate_info'] = get_certificate_info(cert_pem)
            
            if 'ocsp' in operations:
                cert_result['ocsp_status'] = check_ocsp_status(cert_pem)
            
            if 'crl' in operations:
                cert_result['crl_status'] = check_crl_status(cert_pem)
            
            cert_result['success'] = True
            results.append(cert_result)
            
        except Exception as e:
            cert_result['success'] = False
            cert_result['error'] = str(e)
            errors.append(cert_result)
    
    return {
        'success': True,
        'processed': len(results),
        'failed': len(errors),
        'total': len(certificates),
        'results': results,
        'errors': errors
    }


def check_domains_batch(domains: List[Dict], max_workers: int = 5, timeout: int = 10) -> Dict:
    results = []
    errors = []
    
    def check_single_domain(domain_info):
        hostname = domain_info.get('hostname')
        port = domain_info.get('port', 443)
        domain_id = domain_info.get('id', hostname)
        
        try:
            result = check_ssl_certificate(hostname, port, timeout)
            return {
                'id': domain_id,
                'hostname': hostname,
                'port': port,
                'success': True,
                'result': result
            }
        except Exception as e:
            return {
                'id': domain_id,
                'hostname': hostname,
                'port': port,
                'success': False,
                'error': str(e)
            }
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(check_single_domain, domain): domain for domain in domains}
        
        for future in as_completed(future_to_domain):
            try:
                result = future.result()
                if result['success']:
                    results.append(result)
                else:
                    errors.append(result)
            except Exception as e:
                domain = future_to_domain[future]
                errors.append({
                    'id': domain.get('id', domain.get('hostname')),
                    'hostname': domain.get('hostname'),
                    'success': False,
                    'error': str(e)
                })
    
    return {
        'success': True,
        'checked': len(results),
        'failed': len(errors),
        'total': len(domains),
        'results': results,
        'errors': errors
    }


def batch_ocsp_check(certificates: List[str], max_workers: int = 5) -> Dict:
    results = []
    errors = []
    
    def check_single_ocsp(cert_data):
        cert_pem, idx = cert_data
        cert_id = f"cert_{idx + 1}"
        
        try:
            ocsp_result = check_ocsp_status(cert_pem)
            return {
                'id': cert_id,
                'index': idx,
                'success': True,
                'ocsp_status': ocsp_result
            }
        except Exception as e:
            return {
                'id': cert_id,
                'index': idx,
                'success': False,
                'error': str(e)
            }
    
    cert_data_list = [(cert, idx) for idx, cert in enumerate(certificates)]
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cert = {executor.submit(check_single_ocsp, cert_data): cert_data for cert_data in cert_data_list}
        
        for future in as_completed(future_to_cert):
            try:
                result = future.result()
                if result['success']:
                    results.append(result)
                else:
                    errors.append(result)
            except Exception as e:
                cert_data = future_to_cert[future]
                errors.append({
                    'id': f"cert_{cert_data[1] + 1}",
                    'index': cert_data[1],
                    'success': False,
                    'error': str(e)
                })
    
    return {
        'success': True,
        'checked': len(results),
        'failed': len(errors),
        'total': len(certificates),
        'results': sorted(results, key=lambda x: x['index']),
        'errors': sorted(errors, key=lambda x: x['index'])
    }


def batch_crl_check(certificates: List[str], max_workers: int = 3) -> Dict:
    results = []
    errors = []
    
    def check_single_crl(cert_data):
        cert_pem, idx = cert_data
        cert_id = f"cert_{idx + 1}"
        
        try:
            crl_result = check_crl_status(cert_pem)
            return {
                'id': cert_id,
                'index': idx,
                'success': True,
                'crl_status': crl_result
            }
        except Exception as e:
            return {
                'id': cert_id,
                'index': idx,
                'success': False,
                'error': str(e)
            }
    
    cert_data_list = [(cert, idx) for idx, cert in enumerate(certificates)]
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cert = {executor.submit(check_single_crl, cert_data): cert_data for cert_data in cert_data_list}
        
        for future in as_completed(future_to_cert):
            try:
                result = future.result()
                if result['success']:
                    results.append(result)
                else:
                    errors.append(result)
            except Exception as e:
                cert_data = future_to_cert[future]
                errors.append({
                    'id': f"cert_{cert_data[1] + 1}",
                    'index': cert_data[1],
                    'success': False,
                    'error': str(e)
                })
    
    return {
        'success': True,
        'checked': len(results),
        'failed': len(errors),
        'total': len(certificates),
        'results': sorted(results, key=lambda x: x['index']),
        'errors': sorted(errors, key=lambda x: x['index'])
    }
