import dns.resolver
import dns.exception
from typing import List, Dict, Optional, Tuple
from time import time
from functools import wraps
from config import Config
from ui.colors import Colors
from ui.display import gradient_print, get_midnight_gradient_text
from utils.validators import validate_domain
from utils.exceptions import ValidationError, NetworkError
from utils.logger import default_logger
from utils.audit import audit_logger


_dns_cache: Dict[Tuple[str, str], Tuple[List[str], float]] = {}


def _is_cache_valid(timestamp: float) -> bool:
    return (time() - timestamp) < Config.DNS_CACHE_TTL


def _get_cache_key(domain: str, record_type: str) -> Tuple[str, str]:
    return (domain.lower(), record_type.upper())


def _clear_expired_cache():
    current_time = time()
    expired_keys = [
        key for key, (_, timestamp) in _dns_cache.items()
        if (current_time - timestamp) >= Config.DNS_CACHE_TTL
    ]
    for key in expired_keys:
        del _dns_cache[key]


def clear_dns_cache():
    global _dns_cache
    _dns_cache.clear()
    default_logger.debug("DNS cache cleared")


def get_cache_stats() -> Dict[str, int]:
    _clear_expired_cache()
    return {
        "total_entries": len(_dns_cache),
        "valid_entries": len([k for k, (_, ts) in _dns_cache.items() if _is_cache_valid(ts)])
    }


def query_dns_record(domain: str, record_type: str, use_cache: bool = True) -> Optional[List[str]]:
    try:
        validate_domain(domain)
        if record_type not in Config.DNS_RECORD_TYPES:
            raise ValidationError(f"Invalid DNS record type: {record_type}. Allowed: {', '.join(Config.DNS_RECORD_TYPES)}")
        
        if use_cache:
            cache_key = _get_cache_key(domain, record_type)
            if cache_key in _dns_cache:
                results, timestamp = _dns_cache[cache_key]
                if _is_cache_valid(timestamp):
                    default_logger.debug(f"DNS cache hit for {record_type} records of {domain}")
                    audit_logger.log_dns_query(record_type, domain, True, len(results), cached=True)
                    return results.copy()
                else:
                    del _dns_cache[cache_key]
        
        answers = dns.resolver.resolve(domain, record_type)
        results = [rdata.to_text() for rdata in answers]
        
        if use_cache:
            cache_key = _get_cache_key(domain, record_type)
            _dns_cache[cache_key] = (results.copy(), time())
            _clear_expired_cache()
        
        audit_logger.log_dns_query(record_type, domain, True, len(results), cached=False)
        
        return results
    except ValidationError:
        audit_logger.log_dns_query(record_type, domain, False)
        raise
    except dns.resolver.NoAnswer:
        if use_cache:
            cache_key = _get_cache_key(domain, record_type)
            _dns_cache[cache_key] = ([], time())
        audit_logger.log_dns_query(record_type, domain, True, 0)
        return []
    except dns.resolver.NXDOMAIN:
        default_logger.warning(f"Domain '{domain}' does not exist (NXDOMAIN)")
        audit_logger.log_dns_query(record_type, domain, False)
        raise NetworkError(f"Domain '{domain}' does not exist (NXDOMAIN)") from None
    except dns.exception.Timeout:
        default_logger.error(f"DNS query timed out for {record_type} records on {domain}")
        audit_logger.log_dns_query(record_type, domain, False)
        raise NetworkError(f"DNS query timed out for {record_type} records") from None
    except dns.resolver.NoNameservers:
        default_logger.error(f"Could not contact nameservers for {record_type} records on {domain}")
        audit_logger.log_dns_query(record_type, domain, False)
        raise NetworkError(f"Could not contact nameservers for {record_type} records") from None
    except Exception as e:
        default_logger.error(f"Error querying {record_type} records for {domain}: {e}", exc_info=True)
        audit_logger.log_dns_query(record_type, domain, False)
        raise NetworkError(f"Failed to query {record_type} records: {e}") from e


def get_all_dns_records(domain: str) -> Dict[str, List[str]]:
    results = {}
    
    for rtype in Config.DNS_RECORD_TYPES:
        records = query_dns_record(domain, rtype)
        if records is not None:
            results[rtype] = records
    
    return results


def perform_dns_lookup():
    gradient_print("--- DNS Record Lookup ---")
    domain = input(get_midnight_gradient_text("Enter domain name (e.g., google.com): "))
    
    if not domain:
        gradient_print("Domain name cannot be empty.")
        return
    
    try:
        validate_domain(domain)
    except ValidationError as e:
        gradient_print(str(e))
        return
    
    gradient_print(f"Querying DNS records for '{domain}'...")
    
    for rtype in Config.DNS_RECORD_TYPES:
        try:
            gradient_print(f"Querying {rtype} records...")
            answers = query_dns_record(domain, rtype)
            
            if answers is None:
                continue  # Error already printed
            elif answers:
                gradient_print(f"--- {rtype} Records ---")
                for record in answers:
                    gradient_print(f"  {record}")
            else:
                gradient_print(f"  No {rtype} records found.")
        except Exception as e:
            gradient_print(f"Error querying {rtype} records: {e}")
        
        gradient_print("-" * 20)
