#!/usr/bin/env python3
import socket
import struct
from registro import inc_metrica, gerar_corpo_prometheus

BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'


def checksum(dados: bytes) -> int:
    if len(dados) % 2:
        dados = dados + b'\x00'
    s = sum(struct.unpack(f"!{len(dados) // 2}H", dados))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def criar_quadro_eth(dst_mac: bytes, src_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    cab = struct.pack("!6s6sH", dst_mac, src_mac, ethertype)
    quadro = cab + payload
    if len(quadro) < 60:
        quadro = quadro.ljust(60, b'\x00')
    return quadro


def enviar_quadro(iface: dict, dst_mac: bytes, ethertype: int, payload: bytes):
    quadro = criar_quadro_eth(dst_mac, iface["mac_bytes"], ethertype, payload)
    iface["sock"].send(quadro)
    inc_metrica(f"quadros_enviados_{iface['nome']}")


def validar_ipv4(dados_ip: bytes):
    if len(dados_ip) < 20:
        return None
    versao = dados_ip[0] >> 4
    ihl = (dados_ip[0] & 0x0F) * 4
    if versao != 4 or ihl < 20 or len(dados_ip) < ihl:
        return None
    tot_len = struct.unpack("!H", dados_ip[2:4])[0]
    if tot_len < ihl or tot_len > len(dados_ip):
        return None
    if checksum(dados_ip[:ihl]) != 0:
        return None
    return dados_ip[:tot_len]


def criar_pacote_ip(origem_ip_str: str, destino_ip_str: str, protocolo: int, carga: bytes, ttl: int = 64) -> bytes:
    versao_ihl = (4 << 4) | 5
    tot_len = 20 + len(carga)
    ip_orig = socket.inet_aton(origem_ip_str)
    ip_dest = socket.inet_aton(destino_ip_str)
    cab_sem_chk = struct.pack("!BBHHHBBH4s4s", versao_ihl, 0, tot_len, 0, 0, ttl, protocolo, 0, ip_orig, ip_dest)
    chk = checksum(cab_sem_chk)
    cabecalho = struct.pack("!BBHHHBBH4s4s", versao_ihl, 0, tot_len, 0, 0, ttl, protocolo, chk, ip_orig, ip_dest)
    return cabecalho + carga


def decrementar_ttl(pacote_ip: bytes) -> bytes:
    ihl = (pacote_ip[0] & 0x0F) * 4
    cab = bytearray(pacote_ip[:ihl])
    cab[8] -= 1
    cab[10:12] = b'\x00\x00'
    cab[10:12] = struct.pack("!H", checksum(cab))
    return bytes(cab) + pacote_ip[ihl:]


def criar_icmp_erro(tipo: int, codigo: int, pacote_original: bytes, ip_origem: str) -> bytes:
    inc_metrica("icmp_gerados")
    ihl_orig = (pacote_original[0] & 0x0F) * 4
    corpo = pacote_original[:ihl_orig + 8]
    icmp_sem_chk = struct.pack("!BBH4s", tipo, codigo, 0, b'\x00\x00\x00\x00') + corpo
    chk = checksum(icmp_sem_chk)
    icmp_completo = struct.pack("!BBH4s", tipo, codigo, chk, b'\x00\x00\x00\x00') + corpo
    origem_original_str = socket.inet_ntoa(pacote_original[12:16])
    return criar_pacote_ip(ip_origem, origem_original_str, 1, icmp_completo, ttl=64)


def criar_echo_reply(pacote_ip: bytes, ip_destino_req: str):
    ihl = (pacote_ip[0] & 0x0F) * 4
    dados_icmp = pacote_ip[ihl:]
    if len(dados_icmp) < 8:
        return "erro_cabecalho"
    tipo, codigo = dados_icmp[0], dados_icmp[1]
    if tipo != 8 or codigo != 0:
        return "outro_icmp"
    if checksum(dados_icmp) != 0:
        return "erro_cabecalho"

    inc_metrica("icmp_gerados")
    ident_seq = dados_icmp[4:8]
    corpo = dados_icmp[8:]
    icmp_sem_chk = struct.pack("!BBH4s", 0, 0, 0, ident_seq) + corpo
    chk = checksum(icmp_sem_chk)
    icmp_completo = struct.pack("!BBH4s", 0, 0, chk, ident_seq) + corpo
    origem_req_str = socket.inet_ntoa(pacote_ip[12:16])
    return criar_pacote_ip(ip_destino_req, origem_req_str, 1, icmp_completo, ttl=64)


def validar_udp_local(pacote_ip: bytes):
    ihl = (pacote_ip[0] & 0x0F) * 4
    dados_udp = pacote_ip[ihl:]
    if len(dados_udp) < 8:
        return None
    porta_orig, porta_dst, tam_udp, chk_recebido = struct.unpack("!HHHH", dados_udp[:8])
    if tam_udp < 8 or tam_udp > len(dados_udp):
        return None
    segmento_udp = dados_udp[:tam_udp]
    if chk_recebido != 0:
        pseudo = struct.pack("!4s4sBBH", pacote_ip[12:16], pacote_ip[16:20], 0, 17, tam_udp)
        if checksum(pseudo + segmento_udp) != 0:
            return None
    return porta_orig, porta_dst, segmento_udp[8:]


def criar_pacote_udp(ip_orig_str: str, porta_orig: int, ip_dst_str: str, porta_dst: int, payload: bytes) -> bytes:
    tam_udp = 8 + len(payload)
    ip_orig = socket.inet_aton(ip_orig_str)
    ip_dst = socket.inet_aton(ip_dst_str)
    pseudo = struct.pack("!4s4sBBH", ip_orig, ip_dst, 0, 17, tam_udp)
    udp_sem_chk = struct.pack("!HHHH", porta_orig, porta_dst, tam_udp, 0) + payload
    chk = checksum(pseudo + udp_sem_chk)
    if chk == 0:
        chk = 0xFFFF
    udp_completo = struct.pack("!HHHH", porta_orig, porta_dst, tam_udp, chk) + payload
    return criar_pacote_ip(ip_orig_str, ip_dst_str, 17, udp_completo, ttl=64)


def processar_http_udp(dados_app: bytes, arp_entradas: int, arp_pendentes: int) -> bytes:
    """Processa a requisição HTTP/UDP (Seção 10) e retorna os bytes da resposta HTTP."""
    def resp_vazia(status: str) -> bytes:
        inc_metrica("respostas_http")
        return f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n".encode("utf-8")

    # Precisa conter o fim dos cabeçalhos (\r\n\r\n) ou ao menos primeira linha + linha vazia
    if b"\r\n\r\n" not in dados_app and not dados_app.endswith(b"\r\n\r\n"):
        # Caso tenha apenas a request line seguida de \r\n\r\n, b"\r\n\r\n" está presente
        return resp_vazia("400 Bad Request")

    try:
        cabecalho_str = dados_app.split(b"\r\n\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        return resp_vazia("400 Bad Request")

    primeira_linha = cabecalho_str.split("\r\n")[0]
    partes = primeira_linha.split(" ")

    # Exatamente 3 campos separados por um único espaço
    if len(partes) != 3 or "" in partes:
        return resp_vazia("400 Bad Request")

    metodo, caminho, versao = partes
    if versao not in ("HTTP/1.1", "HTTP/1.0"):
        return resp_vazia("400 Bad Request")

    if metodo != "GET":
        return resp_vazia("501 Not Implemented")

    if caminho != "/metrics":
        return resp_vazia("404 Not Found")

    # Monta o corpo ANTES de incrementar respostas_http (Seção 10)
    corpo = gerar_corpo_prometheus(arp_entradas, arp_pendentes)
    inc_metrica("respostas_http")
    cab = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: text/plain; version=0.0.4\r\n"
        f"Content-Length: {len(corpo)}\r\n"
        f"\r\n"
    ).encode("utf-8")
    return cab + corpo


def pode_gerar_erro_icmp(pacote_ip: bytes, chegou_em_broadcast: bool, interfaces: dict) -> bool:
    if chegou_em_broadcast:
        return False
    ihl = (pacote_ip[0] & 0x0F) * 4
    protocolo = pacote_ip[9]
    if protocolo == 1 and len(pacote_ip) >= ihl + 1:
        if pacote_ip[ihl] in (3, 4, 5, 11, 12):
            return False
    if (struct.unpack("!H", pacote_ip[6:8])[0] & 0x1FFF) != 0:
        return False
    origem_bytes = pacote_ip[12:16]
    origem_str = socket.inet_ntoa(origem_bytes)
    b0 = origem_bytes[0]
    if origem_bytes == b'\x00\x00\x00\x00' or b0 == 127 or b0 >= 224:
        return False
    for if_info in interfaces.values():
        if origem_str == if_info["broadcast"]:
            return False
    return True