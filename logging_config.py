"""Structured logging configuration for Google App Engine"""

import json
import logging
import os
import sys
import traceback
from flask import request, has_request_context
from typing import Optional, Dict, Any


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs structured JSON logs for App Engine"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            'severity': record.levelname,
            'message': record.getMessage(),
            'module': record.name,
            'timestamp': self.formatTime(record),
        }
        
        # Add trace ID for request correlation if available
        trace_id = self._get_trace_id()
        if trace_id:
            log_entry['logging.googleapis.com/trace'] = trace_id
            
        # Add source location
        log_entry['logging.googleapis.com/sourceLocation'] = {
            'file': record.pathname,
            'line': record.lineno,
            'function': record.funcName
        }
        
        # Include exception info if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': self.formatException(record.exc_info)
            }
            
        # Add any extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'message', 'exc_info', 'exc_text', 
                          'stack_info', 'asctime']:
                log_entry[key] = value
                
        return json.dumps(log_entry, ensure_ascii=False)
    
    def _get_trace_id(self) -> Optional[str]:
        """Extract trace ID from request headers for log correlation"""
        if not has_request_context():
            return None
            
        trace_header = request.headers.get('X-Cloud-Trace-Context')
        if not trace_header:
            return None
            
        trace_id = trace_header.split('/')[0]
        project_id = os.getenv('GOOGLE_CLOUD_PROJECT', 'unknown-project')
        return f'projects/{project_id}/traces/{trace_id}'


def setup_logging():
    """Configure structured logging for App Engine"""
    
    # Remove default handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create structured handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter())
    
    # Configure root logger
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)
    
    # Set specific loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)


def log_request_info(url: str, method: str = 'GET', **kwargs):
    """Log structured request information"""
    logger = logging.getLogger(__name__)
    
    log_data = {
        'event': 'proxy_request',
        'url': url,
        'method': method,
        'user_agent': request.headers.get('User-Agent') if has_request_context() else None,
        'remote_addr': request.remote_addr if has_request_context() else None
    }
    log_data.update(kwargs)
    
    logger.info('Proxy request initiated', extra=log_data)


def log_request_success(url: str, status_code: int, content_length: int = None):
    """Log successful request"""
    logger = logging.getLogger(__name__)
    
    log_data = {
        'event': 'proxy_success',
        'url': url,
        'status_code': status_code,
        'content_length': content_length
    }
    
    logger.info('Proxy request completed successfully', extra=log_data)


def log_request_error(url: str, error: Exception, status_code: int = None):
    """Log request error with full exception details"""
    logger = logging.getLogger(__name__)
    
    log_data = {
        'event': 'proxy_error',
        'url': url,
        'error_type': type(error).__name__,
        'error_message': str(error),
        'status_code': status_code
    }
    
    logger.error('Proxy request failed', extra=log_data, exc_info=True)


def log_validation_error(url: str, reason: str):
    """Log URL validation error"""
    logger = logging.getLogger(__name__)
    
    log_data = {
        'event': 'validation_error',
        'url': url,
        'reason': reason
    }
    
    logger.warning('URL validation failed', extra=log_data)