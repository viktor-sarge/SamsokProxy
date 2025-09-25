#!/usr/bin/env python3.12
# coding=utf-8
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import logging
import json
import urllib.parse
from flask import Flask, request, Response
import proxypy
from logging_config import setup_logging

# Configure structured logging
setup_logging()

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.route('/')
def main_handler():
    return 'Samsökning cross domain proxy!'

@app.route('/crossdomain')
def crossdomain_handler():
    query_string = request.query_string.decode('utf-8')
    logger.info('Crossdomain request received', extra={
        'event': 'crossdomain_request',
        'query_string': query_string,
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent')
    })
    
    try:
        reply = proxypy.get(query_string)
        logger.info('Crossdomain request completed successfully')
        return Response(reply, content_type='application/json')
    except Exception as e:
        logger.error('Crossdomain request failed', extra={
            'event': 'crossdomain_error',
            'query_string': query_string,
            'error_type': type(e).__name__,
            'error_message': str(e)
        }, exc_info=True)
        # Return error response
        error_reply = '{"status": {"http_code": 500, "reason": "Internal server error"}, "content": null}'
        return Response(error_reply, content_type='application/json', status=500)


@app.route('/gotlib/proxy')
def gotlib_proxy_handler():
    target_url = request.args.get('url')

    if not target_url:
        return Response('Missing url parameter', status=400)

    if 'encore.gotlib.goteborg.se' not in target_url:
        return Response('Unsupported target for Göteborg proxy', status=400)

    logger.info('Göteborg proxy request received', extra={
        'event': 'gotlib_proxy_request',
        'target_url': target_url,
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent')
    })

    query = urllib.parse.urlencode({'url': target_url})

    try:
        proxy_response = proxypy.get(query)
        data = json.loads(proxy_response)

        status = data.get('status', {})
        http_code = status.get('http_code', 500) or 500

        if http_code != 200 or not data.get('content'):
            reason = status.get('reason', 'Göteborg proxy fetch failed')
            logger.error('Göteborg proxy failed', extra={
                'event': 'gotlib_proxy_error',
                'target_url': target_url,
                'status_code': http_code,
                'reason': reason
            })
            return Response(f'Failed to fetch Göteborg content ({reason})', status=http_code)

        logger.info('Göteborg proxy succeeded', extra={
            'event': 'gotlib_proxy_success',
            'target_url': target_url,
            'resolved_url': status.get('resolved_url')
        })

        return Response(data['content'], content_type='text/html; charset=utf-8')

    except Exception as e:
        logger.error('Göteborg proxy unexpected failure', extra={
            'event': 'gotlib_proxy_exception',
            'target_url': target_url,
            'error_type': type(e).__name__,
            'error_message': str(e)
        }, exc_info=True)
        return Response('Göteborg proxy encountered an error', status=500)

if __name__ == '__main__':
    # For local testing
    app.run(host='127.0.0.1', port=8080, debug=True)
