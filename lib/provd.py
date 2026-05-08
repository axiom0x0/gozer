import os
import logging
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler


G = '\033[32m'
RST = '\033[0m'

log = logging.getLogger('provd')


class ProvHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        log.info(f'GET {G}{self.path}{RST} from {self.client_address[0]}')
        if self.server.on_request:
            self.server.on_request('GET', self.path, self.client_address[0])
        super().do_GET()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length else b''
        log.info(f'POST {G}{self.path}{RST} from {self.client_address[0]} ({length} bytes)')
        if self.server.on_request:
            self.server.on_request('POST', self.path, self.client_address[0], body)
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress default stderr logging


class ProvServer:
    def __init__(self, root, bind='0.0.0.0', port=80, on_request=None):
        self.root = os.path.abspath(root)
        self.bind = bind
        self.port = port
        self.on_request = on_request
        self._httpd = None
        self._thread = None

    def start(self):
        os.chdir(self.root)
        self._httpd = HTTPServer((self.bind, self.port), ProvHandler)
        self._httpd.on_request = self.on_request
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        log.info(f'serving {self.root} on {self.bind}:{self.port}')

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
