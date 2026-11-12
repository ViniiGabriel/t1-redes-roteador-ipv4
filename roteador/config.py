#!/usr/bin/env python3
import sys
import socket
import struct


def calcular_broadcast(ip_str, prefixo):
    ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
    mask = (0xFFFFFFFF << (32 - prefixo)) & 0xFFFFFFFF if prefixo > 0 else 0
    bcast_int = (ip_int & mask) | (~mask & 0xFFFFFFFF)
    return socket.inet_ntoa(struct.pack("!I", bcast_int))


def ler_configuracao(caminho_arquivo):
    nome_roteador = None
    interfaces = {}  # nome_if -> {'nome': str, 'ip': str, ...}
    rotas = []       # lista de dicts: {'prefixo': str, 'via': str}
    filtros = []     # lista de dicts com as regras na ordem do arquivo

    with open(caminho_arquivo, 'r') as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith('#'):
                continue
            
            partes = linha.split()
            diretiva = partes[0]

            if diretiva == 'nome':
                nome_roteador = partes[1]

            elif diretiva in ('interface', 'gerencia'):
                nome_if = partes[1]
                ip_str, prefixo_str = partes[2].split('/')
                prefixo = int(prefixo_str)
                mac_str = partes[3].lower()
                
                interfaces[nome_if] = {
                    'nome': nome_if,
                    'ip': ip_str,
                    'prefixo': prefixo,
                    'ip_bytes': socket.inet_aton(ip_str),
                    'mac': mac_str,
                    'mac_bytes': bytes.fromhex(mac_str.replace(":", "")),
                    'broadcast': calcular_broadcast(ip_str, prefixo),
                    'gerencia': (diretiva == 'gerencia')
                }

            elif diretiva == 'rota':
                # formato: rota 10.0.4.0/24 via 10.0.12.2
                rotas.append({
                    'prefixo': partes[1],
                    'via': partes[3]
                })

            elif diretiva == 'filtro':
                # formato: filtro negar udp 10.0.1.0/24 10.0.4.0/24 53
                filtros.append({
                    'acao': partes[1],
                    'protocolo': partes[2],
                    'origem': partes[3],
                    'destino': partes[4],
                    'porta': partes[5]
                })

    return {
        'nome': nome_roteador, 
        'interfaces': interfaces,
        'rotas': rotas,
        'filtros': filtros
    }
