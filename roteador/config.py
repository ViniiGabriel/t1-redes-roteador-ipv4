#!/usr/bin/env python3
import sys, time, json
import socket


def ler_configuracao(caminho_arquivo):
    nome_roteador = None
    interfaces = {}  # nome_if -> {'ip': str, 'prefixo': int, 'mac': str, 'gerencia': bool}
    rotas = []       # lista de dicts: {'prefixo': str, 'via': str}
    filtros = []     # lista de dicts com as regras na ordem do arquivo

    caminho_arquivo = sys.argv[1]

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
                mac_str = partes[3]
                
                interfaces[nome_if] = {
                    'ip': ip_str,
                    'prefixo': int(prefixo_str),
                    "ip_bytes": socket.inet_aton(ip_str),
                    'mac': mac_str,
                    "mac_bytes": bytes.fromhex(mac_str.replace(":", "")),
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
   