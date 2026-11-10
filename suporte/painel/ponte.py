"""Ponte HTTP sobre TCP para HTTP sobre UDP, no gerente, para o Prometheus.

O Prometheus pede http://10.199.199.100:9101/metrics?alvo=192.168.100.1; a ponte
repassa GET /metrics ao roteador num datagrama UDP para a porta 9100, com até 3
tentativas de 1 s, e devolve a resposta do roteador.
"""
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ALVOS = {"192.168.100.1", "192.168.100.2", "192.168.100.3"}


def consultar(alvo):
    req = f"GET /metrics HTTP/1.1\r\nHost: {alvo}:9100\r\n\r\n".encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    try:
        for _ in range(3):
            s.sendto(req, (alvo, 9100))
            try:
                dados, origem = s.recvfrom(65535)
            except socket.timeout:
                continue
            if origem[0] == alvo:
                return dados
    finally:
        s.close()
    return None


class Ponte(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        alvo = parse_qs(url.query).get("alvo", [""])[0]
        if url.path != "/metrics" or alvo not in ALVOS:
            self.send_error(404)
            return
        resposta = consultar(alvo)
        if resposta is None or b"\r\n\r\n" not in resposta:
            self.send_error(502, "o roteador não respondeu")
            return
        cab, corpo = resposta.split(b"\r\n\r\n", 1)
        estado = cab.split(b"\r\n")[0].split(b" ", 2)
        codigo = int(estado[1]) if len(estado) > 1 and estado[1].isdigit() else 502
        self.send_response(codigo)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("10.199.199.100", 9101), Ponte).serve_forever()
