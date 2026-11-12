#!/usr/bin/env python3
import socket
import struct

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


def validar_ipv4(dados_ip: bytes):
    if len(dados_ip) < 20:
        return None
    versao = dados_ip[0] >> 4
    ihl = (dados_ip[0] & 0x0F) * 4
    if versao != 4:
        return None
    if ihl < 20 or len(dados_ip) < ihl:
        return None
    tot_len = struct.unpack("!H", dados_ip[2:4])[0]
    if tot_len < ihl or tot_len > len(dados_ip):
        return None
    if checksum(dados_ip[:ihl]) != 0:
        return None
    return dados_ip[:tot_len]


def criar_pacote_ip(origem_ip_str: str, destino_ip_str: str, protocolo: int, carga: bytes, ttl: int = 64) -> bytes:
    versao_ihl = (4 << 4) | 5
    tos = 0
    tot_len = 20 + len(carga)
    ident = 0
    flags_offset = 0
    cab_sem_chk = struct.pack(
        "!BBHHHBBH4s4s",
        versao_ihl,
        tos,
        tot_len,
        ident,
        flags_offset,
        ttl,
        protocolo,
        0,
        socket.inet_aton(origem_ip_str),
        socket.inet_aton(destino_ip_str)
    )
    chk = checksum(cab_sem_chk)
    cabecalho = struct.pack(
        "!BBHHHBBH4s4s",
        versao_ihl,
        tos,
        tot_len,
        ident,
        flags_offset,
        ttl,
        protocolo,
        chk,
        socket.inet_aton(origem_ip_str),
        socket.inet_aton(destino_ip_str)
    )
    return cabecalho + carga


def decrementar_ttl(pacote_ip: bytes) -> bytes:
    ihl = (pacote_ip[0] & 0x0F) * 4
    cab = bytearray(pacote_ip[:ihl])
    cab[8] -= 1
    cab[10:12] = b'\x00\x00'
    cab[10:12] = struct.pack("!H", checksum(cab))
    return bytes(cab) + pacote_ip[ihl:]


def criar_icmp_erro(tipo: int, codigo: int, pacote_original: bytes, ip_origem: str) -> bytes:
    ihl_orig = (pacote_original[0] & 0x0F) * 4
    corpo = pacote_original[:ihl_orig + 8]
    resto = b'\x00\x00\x00\x00'
    icmp_sem_chk = struct.pack("!BBH4s", tipo, codigo, 0, resto) + corpo
    chk = checksum(icmp_sem_chk)
    icmp_completo = struct.pack("!BBH4s", tipo, codigo, chk, resto) + corpo
    
    origem_original_str = socket.inet_ntoa(pacote_original[12:16])
    return criar_pacote_ip(ip_origem, origem_original_str, 1, icmp_completo, ttl=64)


def criar_echo_reply(pacote_ip: bytes, ip_destino_req: str):
    ihl = (pacote_ip[0] & 0x0F) * 4
    dados_icmp = pacote_ip[ihl:]
    if len(dados_icmp) < 8:
        return None
    if checksum(dados_icmp) != 0:
        return None
    tipo, codigo = dados_icmp[0], dados_icmp[1]
    if tipo != 8 or codigo != 0:
        return None
    ident_seq = dados_icmp[4:8]
    corpo = dados_icmp[8:]
    
    icmp_sem_chk = struct.pack("!BBH4s", 0, 0, 0, ident_seq) + corpo
    chk = checksum(icmp_sem_chk)
    icmp_completo = struct.pack("!BBH4s", 0, 0, chk, ident_seq) + corpo
    
    origem_req_str = socket.inet_ntoa(pacote_ip[12:16])
    return criar_pacote_ip(ip_destino_req, origem_req_str, 1, icmp_completo, ttl=64)


def pode_gerar_erro_icmp(pacote_ip: bytes, chegou_em_broadcast: bool, interfaces: dict) -> bool:
    if chegou_em_broadcast:
        return False

    ihl = (pacote_ip[0] & 0x0F) * 4
    protocolo = pacote_ip[9]

    # Se for mensagem de erro ICMP: tipos 3, 4, 5, 11 e 12
    if protocolo == 1 and len(pacote_ip) >= ihl + 1:
        tipo_icmp = pacote_ip[ihl]
        if tipo_icmp in (3, 4, 5, 11, 12):
            return False

    # Fragmento com deslocamento diferente de zero
    flags_desloc = struct.unpack("!H", pacote_ip[6:8])[0]
    deslocamento = flags_desloc & 0x1FFF
    if deslocamento != 0:
        return False

    # Origem não identifica um único host
    origem_bytes = pacote_ip[12:16]
    origem_str = socket.inet_ntoa(origem_bytes)
    b0 = origem_bytes[0]

    # 0.0.0.0
    if origem_bytes == b'\x00\x00\x00\x00':
        return False
    # 127.0.0.0/8
    if b0 == 127:
        return False
    # 224.0.0.0/4 (224-239) e 240.0.0.0/4 (240-255)
    if b0 >= 224:
        return False

    # Broadcast da rede de qualquer interface do roteador
    for if_info in interfaces.values():
        if origem_str == if_info["broadcast"]:
            return False

    return True
