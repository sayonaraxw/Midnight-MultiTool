"""
Export utilities for saving results to various formats.
Supports JSON, CSV, and TXT formats.
"""

import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from utils.system_info import get_system_info, get_resource_usage
from utils.exceptions import FileOperationError, ValidationError
from utils.logger import default_logger
from utils.validators import validate_file_path


def export_to_json(data: Any, output_path: str, indent: int = 2) -> bool:
    """
    Export data to JSON format.
    
    Args:
        data: Data to export (dict, list, etc.)
        output_path: Path to output JSON file
        indent: JSON indentation (default: 2)
        
    Returns:
        True if successful, False otherwise.
        
    Raises:
        ValidationError: If input validation fails
        FileOperationError: If file operations fail
    """
    try:
        validate_file_path(output_path, check_writable=True)
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'data': data
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=indent, ensure_ascii=False)
        
        default_logger.info(f"Successfully exported data to JSON: {output_path}")
        return True
        
    except ValidationError:
        raise
    except PermissionError as e:
        default_logger.error(f"Permission denied for export file: {output_path}")
        raise FileOperationError(f"Permission denied for export file: {output_path}") from e
    except Exception as e:
        default_logger.error(f"Error exporting to JSON: {e}", exc_info=True)
        raise FileOperationError(f"Failed to export to JSON: {e}") from e


def export_to_csv(data: List[Dict[str, Any]], output_path: str) -> bool:
    """
    Export list of dictionaries to CSV format.
    
    Args:
        data: List of dictionaries to export
        output_path: Path to output CSV file
        
    Returns:
        True if successful, False otherwise.
        
    Raises:
        ValidationError: If input validation fails
        FileOperationError: If file operations fail
    """
    try:
        if not isinstance(data, list):
            raise ValidationError("CSV export requires a list of dictionaries")
        
        if not data:
            raise ValidationError("Cannot export empty data to CSV")
        
        if not all(isinstance(item, dict) for item in data):
            raise ValidationError("All CSV items must be dictionaries")
        
        validate_file_path(output_path, check_writable=True)
        
        fieldnames = set()
        for item in data:
            fieldnames.update(item.keys())
        fieldnames = sorted(list(fieldnames))
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            
            for row in data:
                sanitized_row = {}
                for key, value in row.items():
                    if value is None:
                        sanitized_row[key] = ''
                    elif isinstance(value, (str, int, float, bool)):
                        sanitized_row[key] = value
                    else:
                        sanitized_row[key] = str(value)
                writer.writerow(sanitized_row)
        
        default_logger.info(f"Successfully exported data to CSV: {output_path}")
        return True
        
    except ValidationError:
        raise
    except PermissionError as e:
        default_logger.error(f"Permission denied for export file: {output_path}")
        raise FileOperationError(f"Permission denied for export file: {output_path}") from e
    except Exception as e:
        default_logger.error(f"Error exporting to CSV: {e}", exc_info=True)
        raise FileOperationError(f"Failed to export to CSV: {e}") from e


def export_to_txt(data: Any, output_path: str, format_type: str = "table") -> bool:
    """
    Export data to plain text format.
    
    Args:
        data: Data to export
        output_path: Path to output TXT file
        format_type: Format type ("table", "list", "json-like")
        
    Returns:
        True if successful, False otherwise.
        
    Raises:
        ValidationError: If input validation fails
        FileOperationError: If file operations fail
    """
    try:
        validate_file_path(output_path, check_writable=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            if format_type == "table" and isinstance(data, list) and data and isinstance(data[0], dict):
                fieldnames = set()
                for item in data:
                    fieldnames.update(item.keys())
                fieldnames = sorted(list(fieldnames))
                
                col_widths = {field: len(str(field)) for field in fieldnames}
                for item in data:
                    for field in fieldnames:
                        value_len = len(str(item.get(field, '')))
                        col_widths[field] = max(col_widths[field], value_len)
                
                header = " | ".join(str(field).ljust(col_widths[field]) for field in fieldnames)
                f.write(header + "\n")
                f.write("-" * len(header) + "\n")
                
                for item in data:
                    row = " | ".join(
                        str(item.get(field, '')).ljust(col_widths[field])
                        for field in fieldnames
                    )
                    f.write(row + "\n")
                    
            elif format_type == "list" and isinstance(data, list):
                for i, item in enumerate(data, 1):
                    f.write(f"{i}. {item}\n")
                    
            elif isinstance(data, dict):
                for key, value in data.items():
                    f.write(f"{key}: {value}\n")
                    
            else:
                f.write(str(data))
        
        default_logger.info(f"Successfully exported data to TXT: {output_path}")
        return True
        
    except ValidationError:
        raise
    except PermissionError as e:
        default_logger.error(f"Permission denied for export file: {output_path}")
        raise FileOperationError(f"Permission denied for export file: {output_path}") from e
    except Exception as e:
        default_logger.error(f"Error exporting to TXT: {e}", exc_info=True)
        raise FileOperationError(f"Failed to export to TXT: {e}") from e


def export_scan_results(open_ports: List[int], target: str, output_path: str, 
                       format: str = "json") -> bool:
    """
    Export port scan results to file.
    
    Args:
        open_ports: List of open port numbers
        target: Target IP address or hostname
        output_path: Path to output file
        format: Export format ("json", "csv", "txt")
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        data = {
            'target': target,
            'scan_timestamp': datetime.now().isoformat(),
            'open_ports': open_ports,
            'total_open_ports': len(open_ports)
        }
        
        if format.lower() == "json":
            return export_to_json(data, output_path)
        elif format.lower() == "csv":
            csv_data = [{'port': port, 'status': 'open', 'target': target} 
                       for port in open_ports]
            return export_to_csv(csv_data, output_path)
        elif format.lower() == "txt":
            return export_to_txt(data, output_path, format_type="table")
        else:
            raise ValidationError(f"Unsupported export format: {format}")
            
    except Exception as e:
        default_logger.error(f"Error exporting scan results: {e}", exc_info=True)
        raise


def export_system_info(output_path: str, format: str = "json") -> bool:
    """
    Export system information to file.
    
    Args:
        output_path: Path to output file
        format: Export format ("json", "csv", "txt")
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        system_info = get_system_info()
        resource_info = get_resource_usage()
        
        data = {
            'system_info': system_info,
            'resource_usage': resource_info,
            'export_timestamp': datetime.now().isoformat()
        }
        
        if format.lower() == "json":
            return export_to_json(data, output_path)
        elif format.lower() == "csv":
            csv_data = []
            for key, value in system_info.items():
                csv_data.append({'category': 'system', 'key': key, 'value': str(value)})
            for key, value in resource_info.items():
                csv_data.append({'category': 'resource', 'key': key, 'value': str(value)})
            return export_to_csv(csv_data, output_path)
        elif format.lower() == "txt":
            return export_to_txt(data, output_path, format_type="table")
        else:
            raise ValidationError(f"Unsupported export format: {format}")
            
    except Exception as e:
        default_logger.error(f"Error exporting system info: {e}", exc_info=True)
        raise


def export_history(history_data: List[Dict[str, Any]], output_path: str, 
                  format: str = "json") -> bool:
    """
    Export operation history to file.
    
    Args:
        history_data: List of history entries (dictionaries)
        output_path: Path to output file
        format: Export format ("json", "csv", "txt")
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        data = {
            'history': history_data,
            'total_entries': len(history_data),
            'export_timestamp': datetime.now().isoformat()
        }
        
        if format.lower() == "json":
            return export_to_json(data, output_path)
        elif format.lower() == "csv":
            return export_to_csv(history_data, output_path)
        elif format.lower() == "txt":
            return export_to_txt(data, output_path, format_type="table")
        else:
            raise ValidationError(f"Unsupported export format: {format}")
            
    except Exception as e:
        default_logger.error(f"Error exporting history: {e}", exc_info=True)
        raise
