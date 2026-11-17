#!/usr/bin/env python3
"""Servidor HTTPS didáctico. Solo para laboratorio local."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl, json
from datetime import datetime, timezone


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "servicio": "API de matrículas de laboratorio",
            "estado": "activo",
            "hora_servidor": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length)
        print("Solicitud recibida dentro de TLS:", data.decode("utf-8", errors="replace"))
        body = b'{"resultado":"solicitud recibida por HTTPS"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("Servidor HTTPS escuchando en 0.0.0.0:8443")
    server.serve_forever()
