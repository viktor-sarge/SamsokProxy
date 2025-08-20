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
from flask import Flask, request, Response
import proxypy

app = Flask(__name__)

@app.route('/')
def main_handler():
    return 'Samsökning cross domain proxy!'

@app.route('/crossdomain')
def crossdomain_handler():
    reply = proxypy.get(request.query_string.decode('utf-8'))
    return Response(reply, content_type='application/json')

if __name__ == '__main__':
    # For local testing
    app.run(host='127.0.0.1', port=8080, debug=True)