import httplib
import socket
import hashlib
import hmac

import eventlet
eventlet.monkey_patch()

import BaseHTTPServer
import httplib2
from optparse import OptionParser
import logging
import urlparse

logging.basicConfig()
LOG = logging.getLogger()

parser = OptionParser()
parser.add_option('--instance_id', dest='instance_id')
parser.add_option('--tenant_id', dest='tenant_id')
parser.add_option('--metadata_port', dest='metadata_port', type="int")
parser.add_option('--metadata_server', dest='metadata_server')
parser.add_option('--metadata_secret', dest='metadata_secret')
parser.add_option('--port', dest='port', type="int")    

(options, args) = parser.parse_args()

class NetworkMetadataProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    protocol_version = "HTTP/1.1"
    request_version = protocol_version

    def do_GET(self):
        LOG.debug(("Request: %s"), self)
        try:
            self._proxy_request()
        except Exception:
            LOG.exception('Unexpected error.')
            msg = ('An unknown error has occurred. Please try your request again.')

    def _sign_instance_id(self):
        return hmac.new(options.metadata_secret, options.instance_id, hashlib.sha256).hexdigest()

    def _proxy_request(self):
        headers = {
            'X-Forwarded-For': self.client_address,
            'X-Tenant-ID': options.tenant_id,
            'X-Instance-ID': options.instance_id,
            'X-Instance-ID-Signature': self._sign_instance_id()
        }

        parsed_path = urlparse.urlparse(self.path)

        url = urlparse.urlunsplit((
            'http',
            '%s:%s' % (options.metadata_server, options.metadata_port), 
            parsed_path.path,
            parsed_path.query,
            ''))

        h = httplib2.Http()
        resp, content = h.request(
            url,
            method='GET',
            headers=headers)

        self.send_response(resp.status)
        self.send_header('Connection', 'keep-alive')
        self.send_header('Content-Type', resp['content-type'])
        self.send_header('Content-Length', len(content))
        self.end_headers()
        self.wfile.write(content)

class ProxyDaemon(object):

    def run(self):

        print 'Serving on http://localhost:%s' % options.port
        httpd = BaseHTTPServer.HTTPServer(('localhost', options.port), NetworkMetadataProxyHandler)
        httpd.serve_forever()

if __name__ == '__main__':
    proxy = ProxyDaemon()
    proxy.run()
