""" Module for acting as a proxy for fetching contents of a url """

# Based on this module with some modifications: https://github.com/aymanfarhat/proxypy

import urllib2
import json
import urlparse
import re
from cookielib import CookieJar
import codecs
import pickle

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
    args = dict(urlparse.parse_qsl(qstring))

    reply = {}
    reply["headers"] = {}
    reply["status"] = {}

    if "url" in args and _validateUrl(args["url"]):
        url  = args["url"]
        reply["status"]["url"] = url

        cj = CookieJar()

        if "cookies" in args:
            cookies = pickle.loads(codecs.decode(args["cookies"].encode(), "base64"))
            for c in cookies:
                cj.set_cookie(c)

        opener = urllib2.build_opener(urllib2.HTTPRedirectHandler(), urllib2.HTTPHandler(debuglevel=0), urllib2.HTTPSHandler(debuglevel=0), urllib2.HTTPCookieProcessor(cj))

        try:
            response = opener.open(url, timeout=20)
            reply["content"] = response.read()
            reply["status"]["http_code"] = response.code

            if "headers" in args and args["headers"] == "true":
                reply["headers"] = dict(response.info())

            reply["cookies"] = codecs.encode(pickle.dumps([c for c in cj]), "base64").decode()

        except (urllib2.HTTPError, urllib2.URLError) as e:
            reply["status"]["reason"] = str(e.reason)
            reply["content"] = None
            reply["status"]["http_code"] = e.code if hasattr(e,'code') else 0
    else:
        reply["content"] = None
        reply["status"]["http_code"] = 400
        reply["status"]["reason"] = "The url parameter value is missing or invalid"

    if "encoding" in args:
        encoding = args["encoding"]
    else:
        encoding = "utf-8"

    # Attach callback to reply if jsonp request
    if "callback" in args:
        return "{0}({1})".format(args["callback"], json.dumps(reply, encoding = encoding))

    return json.dumps(reply, encoding = encoding)