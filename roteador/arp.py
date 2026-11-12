#!/usr/bin/env python3
import socket
import struct
import time
from protocolos import BROADCAST_MAC, criar_quadro_eth
from registro import (
    registrar_arp_aprendido,
    registrar_arp_expirado,
    registrar_arp_falhou,
    registrar_descarte
)


class TabelaARP:
    def __init__(self):
        # ip_str -> {"mac": bytes, "tempo": float}
        self.cache = {}
        # ip_str -> {"interface": str, "criacao": float, "tentativas": int, "fila": list}
        self.pendentes = {}

    def obter_mac(self, ip_str: str):
        if ip_str in self.cache:
            return self.cache[ip_str]["mac"]
        return None

    def enviar_requisicao_arp(self, proximo_salto: str, out_if_name: str, config: dict):
        iface = config["interfaces"][out_if_name]
        arp_req = struct.pack(
            "!HHBBH6s4s6s4s",
            1, 0x0800, 6, 4, 1,
            iface["mac_bytes"], iface["ip_bytes"],
            b"\x00" * 6, socket.inet_aton(proximo_salto)
        )
        quadro = criar_quadro_eth(BROADCAST_MAC, iface["mac_bytes"], 0x0806, arp_req)
        iface["sock"].send(quadro)

    def enfileirar(self, proximo_salto: str, out_if_name: str, pacote_ip: bytes,
                   gerado_localmente: bool, pacote_original: bytes, in_if_name: str, config: dict):
        agora = time.time()
        if proximo_salto not in self.pendentes:
            self.enviar_requisicao_arp(proximo_salto, out_if_name, config)
            self.pendentes[proximo_salto] = {
                "interface": out_if_name,
                "criacao": agora,
                "tentativas": 1,
                "fila": []
            }

        pend = self.pendentes[proximo_salto]
        if len(pend["fila"]) >= 16:
            # Fila cheia: descarte fila_arp sem ICMP
            origem_str = socket.inet_ntoa(pacote_ip[12:16])
            destino_str = socket.inet_ntoa(pacote_ip[16:20])
            proto = pacote_ip[9]
            registrar_descarte("fila_arp", origem_str, destino_str, proto)
            return

        pend["fila"].append({
            "pacote_ip": pacote_ip,
            "gerado_localmente": gerado_localmente,
            "pacote_original": pacote_original,
            "in_if_name": in_if_name
        })

    def tratar_quadro_arp(self, quadro: bytes, in_if_name: str, config: dict):
        dados_arp = quadro[14:]
        if len(dados_arp) < 28:
            return

        (
            tipo_hardware,
            tipo_protocolo,
            tam_mac,
            tam_ip,
            operacao,
            mac_remetente,
            ip_remetente,
            mac_alvo,
            ip_alvo
        ) = struct.unpack('!HHBBH6s4s6s4s', dados_arp[:28])

        if (tipo_hardware, tipo_protocolo, tam_mac, tam_ip) != (1, 0x0800, 6, 4):
            return
        if operacao not in (1, 2):
            return

        in_if = config["interfaces"][in_if_name]
        if ip_alvo != in_if["ip_bytes"] or ip_remetente == b'\x00\x00\x00\x00':
            return

        ip_remetente_str = socket.inet_ntoa(ip_remetente)
        self.cache[ip_remetente_str] = {
            "mac": mac_remetente,
            "tempo": time.time()
        }

        registrar_arp_aprendido(ip_remetente_str, mac_remetente.hex(":"), in_if_name)

        # Se havia pacotes esperando este endereço, envia todos eles
        if ip_remetente_str in self.pendentes:
            pend = self.pendentes.pop(ip_remetente_str)
            out_if = config["interfaces"][pend["interface"]]
            for item in pend["fila"]:
                pacote_ip = item["pacote_ip"]
                quadro_ip = criar_quadro_eth(mac_remetente, out_if["mac_bytes"], 0x0800, pacote_ip)
                out_if["sock"].send(quadro_ip)

        # Responde à requisição
        if operacao == 1:
            resposta_arp = struct.pack(
                '!HHBBH6s4s6s4s',
                1, 0x0800, 6, 4, 2,
                in_if["mac_bytes"], in_if["ip_bytes"],
                mac_remetente, ip_remetente
            )
            # Envia unicast para o mac_remetente lido da mensagem ARP
            quadro_resp = criar_quadro_eth(mac_remetente, in_if["mac_bytes"], 0x0806, resposta_arp)
            in_if["sock"].send(quadro_resp)

    def verificar_temporizadores(self, config: dict, callback_falha_arp=None):
        agora = time.time()

        # 1. Expiração do cache (30s)
        expirados = [ip for ip, info in self.cache.items() if agora - info["tempo"] >= 30.0]
        for ip in expirados:
            del self.cache[ip]
            registrar_arp_expirado(ip)

        # 2. Resoluções pendentes (repetições aos 1s, 2s e timeout aos 3s)
        falhas = []
        for ip, pend in list(self.pendentes.items()):
            decorrido = agora - pend["criacao"]
            if decorrido >= 3.0:
                falhas.append(ip)
            elif pend["tentativas"] == 1 and decorrido >= 1.0:
                self.enviar_requisicao_arp(ip, pend["interface"], config)
                pend["tentativas"] = 2
            elif pend["tentativas"] == 2 and decorrido >= 2.0:
                self.enviar_requisicao_arp(ip, pend["interface"], config)
                pend["tentativas"] = 3

        for ip in falhas:
            pend = self.pendentes.pop(ip)
            registrar_arp_falhou(ip, pend["interface"])
            for item in pend["fila"]:
                origem_str = socket.inet_ntoa(item["pacote_ip"][12:16])
                destino_str = socket.inet_ntoa(item["pacote_ip"][16:20])
                proto = item["pacote_ip"][9]
                registrar_descarte("arp", origem_str, destino_str, proto)

                if not item["gerado_localmente"] and callback_falha_arp:
                    callback_falha_arp(item["pacote_original"], item["in_if_name"])
