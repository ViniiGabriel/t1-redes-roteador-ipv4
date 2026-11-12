#!/usr/bin/env python3
import socket
import struct
from protocolos import (
    BROADCAST_MAC,
    criar_quadro_eth,
    validar_ipv4,
    decrementar_ttl,
    criar_icmp_erro,
    criar_echo_reply,
    pode_gerar_erro_icmp
)
from registro import registrar_descarte


def construir_tabela_rotas(config: dict) -> list:
    rotas = []
    # 1. Redes conectadas (interfaces exceto gerência)
    for nome_if, iface in config["interfaces"].items():
        if iface.get("gerencia", False):
            continue
        mask = (0xFFFFFFFF << (32 - iface["prefixo"])) & 0xFFFFFFFF if iface["prefixo"] > 0 else 0
        ip_int = struct.unpack("!I", iface["ip_bytes"])[0]
        rede_int = ip_int & mask
        rotas.append({
            "rede": rede_int,
            "prefixo": iface["prefixo"],
            "via": None,
            "interface": nome_if,
            "conectada": True
        })

    # 2. Rotas estáticas
    for r in config.get("rotas", []):
        pref_str, len_str = r["prefixo"].split('/')
        pref_len = int(len_str)
        mask = (0xFFFFFFFF << (32 - pref_len)) & 0xFFFFFFFF if pref_len > 0 else 0
        rede_int = struct.unpack("!I", socket.inet_aton(pref_str))[0] & mask

        via_str = r["via"]
        via_int = struct.unpack("!I", socket.inet_aton(via_str))[0]

        # Encontra a interface da rede conectada que contém o próximo salto
        out_if = None
        for cr in rotas:
            if cr["conectada"]:
                cmask = (0xFFFFFFFF << (32 - cr["prefixo"])) & 0xFFFFFFFF if cr["prefixo"] > 0 else 0
                if (via_int & cmask) == cr["rede"]:
                    out_if = cr["interface"]
                    break

        if out_if is not None:
            rotas.append({
                "rede": rede_int,
                "prefixo": pref_len,
                "via": via_str,
                "interface": out_if,
                "conectada": False
            })

    return rotas


def buscar_rota(tabela_rotas: list, dest_ip_str: str):
    dest_int = struct.unpack("!I", socket.inet_aton(dest_ip_str))[0]
    melhor = None
    for r in tabela_rotas:
        mask = (0xFFFFFFFF << (32 - r["prefixo"])) & 0xFFFFFFFF if r["prefixo"] > 0 else 0
        if (dest_int & mask) == r["rede"]:
            if melhor is None:
                melhor = r
            elif r["prefixo"] > melhor["prefixo"]:
                melhor = r
            elif r["prefixo"] == melhor["prefixo"] and r["conectada"] and not melhor["conectada"]:
                melhor = r

    if melhor is None:
        return None
    prox_salto = melhor["via"] if melhor["via"] is not None else dest_ip_str
    return melhor["interface"], prox_salto


def enviar_ip(pacote_ip: bytes, out_if_name: str, proximo_salto: str, config: dict,
              tabela_arp, gerado_localmente: bool, pacote_original: bytes = None, in_if_name: str = None):
    out_if = config["interfaces"][out_if_name]
    mac_dst = tabela_arp.obter_mac(proximo_salto)
    if mac_dst is not None:
        quadro = criar_quadro_eth(mac_dst, out_if["mac_bytes"], 0x0800, pacote_ip)
        out_if["sock"].send(quadro)
    else:
        tabela_arp.enfileirar(
            proximo_salto,
            out_if_name,
            pacote_ip,
            gerado_localmente,
            pacote_original,
            in_if_name,
            config
        )


def tratar_falha_arp_icmp(pacote_original: bytes, in_if_name: str, config: dict, tabela_rotas: list, tabela_arp):
    if not pode_gerar_erro_icmp(pacote_original, False, config["interfaces"]):
        return
    ip_origem_icmp = config["interfaces"][in_if_name]["ip"]
    icmp_erro = criar_icmp_erro(3, 1, pacote_original, ip_origem_icmp)
    origem_original_str = socket.inet_ntoa(pacote_original[12:16])

    if config["interfaces"][in_if_name]["gerencia"]:
        enviar_ip(icmp_erro, in_if_name, origem_original_str, config, tabela_arp, gerado_localmente=True)
    else:
        rota = buscar_rota(tabela_rotas, origem_original_str)
        if rota is not None:
            out_if_name, prox = rota
            enviar_ip(icmp_erro, out_if_name, prox, config, tabela_arp, gerado_localmente=True)
        else:
            registrar_descarte("sem_rota", ip_origem_icmp, origem_original_str, 1)


def processar_ipv4(quadro: bytes, in_if_name: str, config: dict, tabela_rotas: list, tabela_arp):
    dados_ip = quadro[14:]
    pacote_ip = validar_ipv4(dados_ip)
    if pacote_ip is None:
        # Descarte motivo cabecalho (sem registro na saída padrão)
        return

    origem_ip = socket.inet_ntoa(pacote_ip[12:16])
    dest_ip = socket.inet_ntoa(pacote_ip[16:20])
    proto = pacote_ip[9]
    ttl = pacote_ip[8]
    chegou_em_broadcast = (quadro[:6] == BROADCAST_MAC)

    # Passo 2: Broadcast e Multicast
    if dest_ip == "255.255.255.255" or (pacote_ip[16] >= 224 and pacote_ip[16] <= 239):
        registrar_descarte("local", origem_ip, dest_ip, proto)
        return

    for if_info in config["interfaces"].values():
        if dest_ip == if_info["broadcast"]:
            registrar_descarte("local", origem_ip, dest_ip, proto)
            return

    # Passo 3: Entrega local
    ips_locais = {info["ip"]: info for info in config["interfaces"].values()}
    if dest_ip in ips_locais:
        dst_if = ips_locais[dest_ip]
        in_if = config["interfaces"][in_if_name]

        # Descarte se gerencia -> dados ou dados -> gerencia
        if dst_if["gerencia"] and not in_if["gerencia"]:
            registrar_descarte("local", origem_ip, dest_ip, proto)
            return
        if not dst_if["gerencia"] and in_if["gerencia"]:
            registrar_descarte("local", origem_ip, dest_ip, proto)
            return

        # ICMP echo request
        if proto == 1:
            reply = criar_echo_reply(pacote_ip, dest_ip)
            if reply is None:
                return  # Falha de validação ICMP (descarte cabecalho)

            if in_if["gerencia"]:
                enviar_ip(reply, in_if_name, origem_ip, config, tabela_arp, gerado_localmente=True)
            else:
                rota = buscar_rota(tabela_rotas, origem_ip)
                if rota is not None:
                    out_if_name, prox = rota
                    enviar_ip(reply, out_if_name, prox, config, tabela_arp, gerado_localmente=True)
                else:
                    registrar_descarte("sem_rota", dest_ip, origem_ip, 1)
            return

        # UDP (porta sem serviço gera 3/3 e descarte local)
        if proto == 17:
            registrar_descarte("local", origem_ip, dest_ip, proto)
            if pode_gerar_erro_icmp(pacote_ip, chegou_em_broadcast, config["interfaces"]):
                icmp_erro = criar_icmp_erro(3, 3, pacote_ip, dest_ip)
                if in_if["gerencia"]:
                    enviar_ip(icmp_erro, in_if_name, origem_ip, config, tabela_arp, gerado_localmente=True)
                else:
                    rota = buscar_rota(tabela_rotas, origem_ip)
                    if rota is not None:
                        out_if_name, prox = rota
                        enviar_ip(icmp_erro, out_if_name, prox, config, tabela_arp, gerado_localmente=True)
                    else:
                        registrar_descarte("sem_rota", dest_ip, origem_ip, 1)
            return

        # Outros protocolos
        registrar_descarte("local", origem_ip, dest_ip, proto)
        return

    # Passo 4: Filtragem e pacotes em mgmt0
    if config["interfaces"][in_if_name]["gerencia"]:
        registrar_descarte("local", origem_ip, dest_ip, proto)
        return

    # Passo 5: TTL
    if ttl <= 1:
        registrar_descarte("ttl", origem_ip, dest_ip, proto)
        if pode_gerar_erro_icmp(pacote_ip, chegou_em_broadcast, config["interfaces"]):
            ip_origem_icmp = config["interfaces"][in_if_name]["ip"]
            icmp_erro = criar_icmp_erro(11, 0, pacote_ip, ip_origem_icmp)
            rota = buscar_rota(tabela_rotas, origem_ip)
            if rota is not None:
                out_if_name, prox = rota
                enviar_ip(icmp_erro, out_if_name, prox, config, tabela_arp, gerado_localmente=True)
            else:
                registrar_descarte("sem_rota", ip_origem_icmp, origem_ip, 1)
        return

    # Passo 6: Rota
    rota = buscar_rota(tabela_rotas, dest_ip)
    if rota is None:
        registrar_descarte("sem_rota", origem_ip, dest_ip, proto)
        if pode_gerar_erro_icmp(pacote_ip, chegou_em_broadcast, config["interfaces"]):
            ip_origem_icmp = config["interfaces"][in_if_name]["ip"]
            icmp_erro = criar_icmp_erro(3, 0, pacote_ip, ip_origem_icmp)
            rota_volta = buscar_rota(tabela_rotas, origem_ip)
            if rota_volta is not None:
                out_if_name, prox = rota_volta
                enviar_ip(icmp_erro, out_if_name, prox, config, tabela_arp, gerado_localmente=True)
            else:
                registrar_descarte("sem_rota", ip_origem_icmp, origem_ip, 1)
        return

    out_if_name, prox_salto = rota

    # Passo 7: Encaminhamento
    pacote_encaminhado = decrementar_ttl(pacote_ip)
    enviar_ip(
        pacote_encaminhado,
        out_if_name,
        prox_salto,
        config,
        tabela_arp,
        gerado_localmente=False,
        pacote_original=pacote_ip,
        in_if_name=in_if_name
    )
