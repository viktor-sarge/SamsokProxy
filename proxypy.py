""" Module for acting as a proxy for fetching contents of a url """

# Based on this module with some modifications: https://github.com/aymanfarhat/proxypy
# Updated for Python 3 compatibility

import urllib.request
import urllib.parse
import urllib.error
import json
import re
from http.cookiejar import CookieJar
import codecs
import pickle
import base64
import ssl
import gzip
import io
import logging

logger = logging.getLogger(__name__)

def _validateUrl(urlstr):
    pattern = re.compile(
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    protocol = re.match(r'^(\w+)://',urlstr)

    # if a protocol is specified make sure its only http or https
    if (protocol != None) and not(bool(re.match(r'(?:http)s?',protocol.groups()[0]))):
        return False

    return bool(re.search(pattern,urlstr))

def get(qstring):
    """ Builds and returns a JSON reply of all information and requested data """
    args = dict(urllib.parse.parse_qsl(qstring))

    reply = {}
    reply["headers"] = {}
    reply["status"] = {}

    if "url" in args and _validateUrl(args["url"]):
        url  = args["url"]
        reply["status"]["url"] = url
        
        logger.info('Processing proxy request', extra={
            'event': 'proxy_request_start',
            'url': url,
            'method': args.get('method', 'GET'),
            'has_cookies': 'cookies' in args,
            'has_custom_headers': 'headers' in args and args['headers'] != 'true'
        })

        cj = CookieJar()

        # Handle cookies - support both legacy and plain string formats
        use_cookie_header = False
        cookie_header_value = None
        
        if "cookies" in args:
            try:
                # Try legacy format first (backwards compatibility)
                cookies = pickle.loads(base64.b64decode(args["cookies"]))
                for c in cookies:
                    cj.set_cookie(c)
                logger.debug('Using legacy cookie format')
            except Exception as e:
                # Fall back to plain cookie string format
                cookie_header_value = args["cookies"]
                use_cookie_header = True
                logger.debug('Using plain cookie string format', extra={
                    'cookie_parse_error': str(e)
                })

        # Create SSL context that doesn't verify certificates (for local testing)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Build opener based on cookie format
        if use_cookie_header and cookie_header_value:
            # For plain cookie strings, add as header
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler(), 
                                               urllib.request.HTTPHandler(debuglevel=0), 
                                               urllib.request.HTTPSHandler(debuglevel=0, context=ssl_context))
            opener.addheaders = [('Cookie', cookie_header_value)]
        else:
            # For legacy format or no cookies, use cookie processor
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler(), 
                                               urllib.request.HTTPHandler(debuglevel=0), 
                                               urllib.request.HTTPSHandler(debuglevel=0, context=ssl_context), 
                                               urllib.request.HTTPCookieProcessor(cj))

        try:
            # Determine HTTP method (default to GET for backwards compatibility)
            method = args.get("method", "GET").upper()
            
            # Prepare request data and headers
            request_data = None
            content_type = None
            
            if method == "POST":
                # Handle POST data
                if "postData" in args:
                    request_data = args["postData"].encode('utf-8')
                
                # Handle content type
                if "contentType" in args:
                    content_type = args["contentType"]
                else:
                    content_type = "application/x-www-form-urlencoded"
            
            # Create the request object
            req = urllib.request.Request(url, data=request_data, method=method)
            
            # Add content type header for POST requests
            if method == "POST" and content_type:
                req.add_header('Content-Type', content_type)
            
            # Handle custom headers
            if "headers" in args and args["headers"] != "true":
                try:
                    custom_headers = json.loads(args["headers"])
                    for header_name, header_value in custom_headers.items():
                        # Skip headers that urllib handles automatically or that cause issues
                        if header_name.lower() not in ['content-length', 'connection', 'host']:
                            req.add_header(header_name, header_value)
                except (json.JSONDecodeError, TypeError):
                    # If headers can't be parsed, ignore them
                    pass
            
            # Make the request
            response = opener.open(req, timeout=20)
            
            # Read the raw response
            raw_content = response.read()
            content_encoding = response.headers.get('content-encoding')
            
            # Handle compressed responses automatically
            try:
                # Check if the response is gzip compressed
                if content_encoding == 'gzip':
                    content = gzip.decompress(raw_content).decode('utf-8', errors='ignore')
                    logger.debug('Decompressed gzip response')
                elif content_encoding == 'deflate':
                    import zlib
                    content = zlib.decompress(raw_content).decode('utf-8', errors='ignore')
                    logger.debug('Decompressed deflate response')
                elif content_encoding == 'br':
                    import brotli
                    content = brotli.decompress(raw_content).decode('utf-8', errors='ignore')
                    logger.debug('Decompressed brotli response')
                else:
                    content = raw_content.decode('utf-8', errors='ignore')
            except Exception as e:
                # If decompression fails, try as plain text
                content = raw_content.decode('utf-8', errors='ignore')
                logger.warning('Failed to decompress response, using as plain text', extra={
                    'content_encoding': content_encoding,
                    'decompression_error': str(e)
                })
            
            reply["content"] = content
            reply["status"]["http_code"] = response.code

            # Return response headers if requested
            if "headers" in args and args["headers"] == "true":
                reply["headers"] = dict(response.info())

            reply["cookies"] = base64.b64encode(pickle.dumps([c for c in cj])).decode()
            
            logger.info('Proxy request completed successfully', extra={
                'event': 'proxy_success',
                'url': url,
                'status_code': response.code,
                'content_length': len(content),
                'content_encoding': content_encoding
            })

        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            error_code = e.code if hasattr(e, 'code') else 0
            error_reason = str(e.reason) if hasattr(e, 'reason') else str(e)
            
            reply["status"]["reason"] = error_reason
            reply["content"] = None
            reply["status"]["http_code"] = error_code
            
            logger.error('Proxy request failed', extra={
                'event': 'proxy_error',
                'url': url,
                'error_type': type(e).__name__,
                'error_code': error_code,
                'error_reason': error_reason
            }, exc_info=True)
    else:
        provided_url = args.get("url", "")
        reply["content"] = None
        reply["status"]["http_code"] = 400
        reply["status"]["reason"] = "The url parameter value is missing or invalid"
        
        logger.warning('URL validation failed', extra={
            'event': 'validation_error',
            'provided_url': provided_url,
            'reason': 'URL missing or invalid format'
        })

    if "encoding" in args:
        encoding = args["encoding"]
    else:
        encoding = "utf-8"

    # Attach callback to reply if jsonp request
    if "callback" in args:
        return "{0}({1})".format(args["callback"], json.dumps(reply, ensure_ascii=False))

    return json.dumps(reply, ensure_ascii=False)