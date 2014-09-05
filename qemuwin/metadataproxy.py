import httplib
import socket
import hashlib
import hmac
import os
import tempfile
import multiprocessing

import BaseHTTPServer
import httplib2
from optparse import OptionParser
import logging
import urlparse

logging.basicConfig()
LOG = logging.getLogger()

parser = OptionParser()
parser.add_option('--instance_dir', dest='instance_dir')
parser.add_option('--instance_id', dest='instance_id')
parser.add_option('--tenant_id', dest='tenant_id')
parser.add_option('--metadata_port', dest='metadata_port', type="int")
parser.add_option('--metadata_server', dest='metadata_server')
parser.add_option('--metadata_secret', dest='metadata_secret')
parser.add_option('--port', dest='port', type="int")    

(cmd_options, args) = parser.parse_args()

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
        return hmac.new(options['metadata_secret'], options['instance_id'], hashlib.sha256).hexdigest()

    def _proxy_request(self):
        headers = {
            'X-Forwarded-For': self.client_address,
            'X-Tenant-ID': options['tenant_id'],
            'X-Instance-ID': options['instance_id'],
            'X-Instance-ID-Signature': self._sign_instance_id()
        }

        parsed_path = urlparse.urlparse(self.path)

        url = urlparse.urlunsplit((
            'http',
            '%s:%s' % (options['metadata_server'], options['metadata_port']), 
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

        print 'Serving on http://localhost:%s' % options['port']
        httpd = BaseHTTPServer.HTTPServer(('localhost', options['port']), NetworkMetadataProxyHandler)
        httpd.serve_forever()

def run_proxy_deamon(instance_dir, instance_id, tenant_id, metadata_port, 
                     metadata_server, metadata_secret, port):
    with open(os.path.join(instance_dir, 'metadataproxy.pid'), 'w+') as pidfile:
        pidfile.write(str(os.getpid()))
    global options
    options = {'instance_id': instance_id, 'tenant_id': tenant_id, 
               'metadata_port': metadata_port, 'metadata_server': metadata_server, 
               'metadata_secret': metadata_secret, 'port': port}
    print options
    proxy = ProxyDaemon()
    proxy.run()

if __name__ == '__main__':
    print cmd_options
    metadata_process = multiprocessing.Process(target=run_proxy_deamon, 
                                               args=(cmd_options.instance_dir, cmd_options.instance_id, cmd_options.tenant_id, 
                                                     cmd_options.metadata_port, cmd_options.metadata_server, 
                                                     cmd_options.metadata_secret, cmd_options.port,))
    metadata_process.daemon = True
    metadata_process.start()
