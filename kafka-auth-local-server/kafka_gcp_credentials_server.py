# -*- coding: utf-8 -*-
# Copyright 2022 Google LLC
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

import base64
import datetime
import http.server
import json
import google.auth
import google.auth.crypt
import google.auth.jwt
import google.auth.transport.urllib3
import urllib3


_credentials, _project = google.auth.default(
    scopes=['https://www.googleapis.com/auth/cloud-platform']
)
_http_client = urllib3.PoolManager()


def valid_credentials():
  if not _credentials.valid:
    _credentials.refresh(google.auth.transport.urllib3.Request(_http_client))
  return _credentials


_HEADER = json.dumps(dict(typ='JWT', alg='GOOG_OAUTH2_TOKEN'))


def get_jwt(creds):
  return json.dumps(
      dict(
          exp=creds.expiry.replace(tzinfo=datetime.timezone.utc).timestamp(),
          iss='Google',
          iat=datetime.datetime.now(datetime.timezone.utc).timestamp(),
          sub=creds.service_account_email,
      )
  )


def b64_encode(source):
  return (
      base64.urlsafe_b64encode(source.encode('utf-8'))
      .decode('utf-8')
      .rstrip('=')
  )


def get_kafka_access_token(creds):
  return '.'.join(
      [b64_encode(_HEADER), b64_encode(get_jwt(creds)), b64_encode(creds.token)]
  )


def build_message():
  creds = valid_credentials()
  expiry_seconds = (
      creds.expiry.replace(tzinfo=datetime.timezone.utc) - datetime.datetime.now(datetime.timezone.utc)
  ).total_seconds()
  return json.dumps(
      dict(
          access_token=get_kafka_access_token(creds),
          token_type='Bearer',
          expires_in=expiry_seconds,
      )
  )


class AuthHandler(http.server.BaseHTTPRequestHandler):
  """Handles HTTP requests for the GCP credentials server."""

  def _handle(self):
    self.send_response(200)
    self.send_header('Content-type', 'application/json')
    self.end_headers()
    message = build_message().encode('utf-8')
    self.wfile.write(message)

  def do_GET(self):
    """Handles GET requests."""
    self._handle()

  def do_POST(self):
    """Handles POST requests."""
    self._handle()


def run_server():
  server_address = ('localhost', 14293)
  server = http.server.ThreadingHTTPServer(server_address, AuthHandler)
  print(
      'Serving on localhost:14293. This is not accessible outside of the '
      'current machine.'
  )
  server.serve_forever()


if __name__ == '__main__':
  run_server()
