"""
Static Proxy Manager for proxy-cheap.com or similar services
Simple, reliable proxy routing for blocked domains
"""

import urllib.request
import urllib.parse
import urllib.error
import logging
import os
import ssl
from http.cookiejar import CookieJar

# Load environment variables from .env file (development) or system (production)
import env_loader

logger = logging.getLogger(__name__)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Helper handler that prevents automatic redirect following"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # pragma: no cover - thin wrapper
        return None

class StaticProxyManager:
    """Manages a single static residential proxy for blocked domains"""
    
    def __init__(self):
        # These should be set via environment variables in production
        self.proxy_host = os.getenv('STATIC_PROXY_HOST', '')  # e.g., '123.45.67.89'
        self.proxy_port = os.getenv('STATIC_PROXY_PORT', '8000')  # e.g., '8000'
        self.proxy_username = os.getenv('STATIC_PROXY_USERNAME', '')  # from proxy-cheap
        self.proxy_password = os.getenv('STATIC_PROXY_PASSWORD', '')  # from proxy-cheap
        
        # For local testing, you can set these directly:
        # self.proxy_host = 'YOUR_PROXY_IP'
        # self.proxy_port = 'YOUR_PROXY_PORT' 
        # self.proxy_username = 'YOUR_USERNAME'
        # self.proxy_password = 'YOUR_PASSWORD'
    
    def is_configured(self) -> bool:
        """Check if proxy is properly configured"""
        return bool(self.proxy_host and self.proxy_username and self.proxy_password)
    
    def should_use_proxy(self, url: str) -> bool:
        """Determine if URL should use the static proxy"""
        blocked_domains = [
            'bibliotekskatalog.falkenberg.se',
            'encore.gotlib.goteborg.se',
            'kohaopac.alingsas.se'  # Blocks Google Cloud IPs in production
        ]
        
        if not self.is_configured():
            logger.warning("Static proxy not configured, skipping proxy routing")
            return False
        
        for domain in blocked_domains:
            if domain in url:
                logger.info(f"URL {url} will use static proxy (matches {domain})")
                return True
        
        return False
    
    def build_proxy_opener(self, cookie_jar: CookieJar | None = None, allow_redirects: bool = True):
        """Build urllib opener configured with the static proxy"""
        if not self.is_configured():
            raise ValueError("Static proxy not configured")
        
        # Build proxy URL with authentication
        proxy_url = f"http://{self.proxy_username}:{self.proxy_password}@{self.proxy_host}:{self.proxy_port}"
        
        # Create proxy handler
        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        
        # Create password manager for authentication (backup method)
        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(
            None, 
            f"http://{self.proxy_host}:{self.proxy_port}",
            self.proxy_username, 
            self.proxy_password
        )
        
        auth_handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
        
        # Create SSL context that doesn't verify certificates (needed for proxies)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Build opener with redirect and optional cookie support
        handlers = [
            proxy_handler,
            auth_handler,
            urllib.request.HTTPHandler(),
            urllib.request.HTTPSHandler(context=ssl_context)
        ]

        if allow_redirects:
            handlers.append(urllib.request.HTTPRedirectHandler())
        else:
            handlers.append(_NoRedirectHandler())

        if cookie_jar is not None:
            handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))

        opener = urllib.request.build_opener(*handlers)
        
        return opener
    
    def make_request(
        self,
        req: urllib.request.Request,
        timeout: int = 20,
        cookie_jar: CookieJar | None = None,
        allow_redirects: bool = True
    ):
        """Make request through the static proxy"""
        if not self.is_configured():
            raise ValueError("Static proxy not configured")
        
        logger.info(f"Making request through static proxy: {self.proxy_host}:{self.proxy_port}")
        
        try:
            opener = self.build_proxy_opener(cookie_jar=cookie_jar, allow_redirects=allow_redirects)
            response = opener.open(req, timeout=timeout)
            
            logger.info("Static proxy request successful")
            return response
            
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                logger.info(
                    "Static proxy received redirect",
                    extra={
                        'status_code': e.code,
                        'redirect_location': e.headers.get('Location'),
                        'url': req.full_url
                    }
                )
                raise
            logger.error(f"Static proxy HTTP error: {e.code} - {e.reason}")
            raise
        except urllib.error.URLError as e:
            logger.error(f"Static proxy connection error: {e.reason}")
            raise
        except Exception as e:
            logger.error(f"Static proxy unexpected error: {e}")
            raise


# Global instance
_static_proxy_manager = None

def get_static_proxy_manager() -> StaticProxyManager:
    """Get or create the global static proxy manager"""
    global _static_proxy_manager
    if _static_proxy_manager is None:
        _static_proxy_manager = StaticProxyManager()
    return _static_proxy_manager


# Configuration helper for easy setup
def configure_static_proxy(host: str, port: str, username: str, password: str):
    """Configure the static proxy (for testing/development)"""
    global _static_proxy_manager
    _static_proxy_manager = StaticProxyManager()
    _static_proxy_manager.proxy_host = host
    _static_proxy_manager.proxy_port = port
    _static_proxy_manager.proxy_username = username
    _static_proxy_manager.proxy_password = password
    
    logger.info(f"Static proxy configured: {host}:{port} with username {username}")


def test_static_proxy_connection():
    """Test the static proxy connection"""
    manager = get_static_proxy_manager()
    
    if not manager.is_configured():
        return {
            'success': False,
            'error': 'Proxy not configured'
        }
    
    # Test with a simple HTTP request
    test_url = 'http://httpbin.org/ip'
    
    try:
        req = urllib.request.Request(test_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (compatible; StaticProxyTest/1.0)')
        
        response = manager.make_request(req, timeout=10)
        content = response.read().decode('utf-8')
        
        import json
        result = json.loads(content)
        proxy_ip = result.get('origin', 'unknown')
        
        logger.info(f"Static proxy test successful. Proxy IP: {proxy_ip}")
        
        return {
            'success': True,
            'proxy_ip': proxy_ip,
            'status_code': response.code
        }
        
    except Exception as e:
        logger.error(f"Static proxy test failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }
