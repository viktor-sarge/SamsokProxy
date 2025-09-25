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
        original_url = url
        
        logger.info('Processing proxy request', extra={
            'event': 'proxy_request_start',
            'url': original_url,
            'method': args.get('method', 'GET'),
            'has_cookies': 'cookies' in args,
            'has_custom_headers': 'headers' in args and args['headers'] != 'true'
        })

        reply["status"]["url"] = original_url

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

            # Ensure we always send a reasonable User-Agent (some providers block default urllib)
            if not req.has_header('User-Agent'):
                req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36')
            
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
            
            # Check if this URL needs static proxy (for blocked domains)
            from static_proxy_manager import get_static_proxy_manager
            
            static_proxy = get_static_proxy_manager()
            
            if static_proxy.should_use_proxy(url):
                logger.info('URL requires static proxy', extra={
                    'event': 'static_proxy_required',
                    'url': url
                })
                
                # Add cookie header to request if we have cookies
                if use_cookie_header and cookie_header_value:
                    req.add_header('Cookie', cookie_header_value)
                    logger.debug('Added Cookie header to static proxy request')
                
                def _attempt_gotlib_handshake() -> urllib.request.addinfourl:
                    """Perform Göteborg request by emulating Encore CAS redirect flow"""
                    headers = {name: value for name, value in req.header_items()}
                    if 'User-Agent' not in headers:
                        headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'

                    current_url = url
                    max_redirects = 6

                    for attempt in range(max_redirects):
                        head_req = urllib.request.Request(current_url, method='HEAD')
                        for header_name, header_value in headers.items():
                            head_req.add_header(header_name, header_value)

                        try:
                            # Expect redirect chain without automatically following
                            static_proxy.make_request(
                                head_req,
                                timeout=20,
                                cookie_jar=cj,
                                allow_redirects=False
                            )
                            # No redirect, break and fetch current URL directly
                            break
                        except urllib.error.HTTPError as redirect_error:
                            if redirect_error.code not in (301, 302, 303, 307, 308):
                                raise

                            location = redirect_error.headers.get('Location')
                            if not location:
                                raise RuntimeError('Göteborg redirect missing Location header')

                            resolved_location = urllib.parse.urljoin(current_url, location)
                            parsed = urllib.parse.urlparse(resolved_location)
                            target_values = urllib.parse.parse_qs(parsed.query).get('url')

                            if target_values:
                                target_url = target_values[0]
                                follow_req = urllib.request.Request(target_url)
                                for header_name, header_value in headers.items():
                                    follow_req.add_header(header_name, header_value)

                                return static_proxy.make_request(
                                    follow_req,
                                    timeout=20,
                                    cookie_jar=cj
                                )

                            # No CAS target in redirect – treat as intermediate hop (e.g., http -> https)
                            current_url = resolved_location
                    else:
                        raise RuntimeError('Göteborg redirect chain exceeded maximum depth')

                    follow_req = urllib.request.Request(current_url)
                    for header_name, header_value in headers.items():
                        follow_req.add_header(header_name, header_value)

                    return static_proxy.make_request(
                        follow_req,
                        timeout=20,
                        cookie_jar=cj
                    )

                gotlib_domain = 'gotlib.goteborg.se'

                try:
                    if gotlib_domain in url:
                        logger.info('Göteborg request routed via static proxy handshake', extra={
                            'event': 'static_proxy_gotlib_handshake',
                            'url': url
                        })
                        response = _attempt_gotlib_handshake()
                        logger.info('Göteborg handshake completed via static proxy', extra={
                            'event': 'static_proxy_gotlib_success',
                            'url': url
                        })
                    else:
                        # Use static proxy for other blocked domains
                        response = static_proxy.make_request(
                            req,
                            timeout=20,
                            cookie_jar=cj
                        )
                        logger.info('Request completed via static proxy', extra={
                            'event': 'static_proxy_success',
                            'url': url,
                            'proxy_host': static_proxy.proxy_host
                        })
                except Exception as e:
                    logger.error('Static proxy failed', extra={
                        'event': 'static_proxy_failure',
                        'url': url,
                        'error': str(e)
                    }, exc_info=True)
                    raise
            else:
                # Make the request normally for non-blocked domains
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
