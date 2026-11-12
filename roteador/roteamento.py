#!/usr/bin/env python3
import socket
import struct
import ipaddress
from protocolos import (
    BROADCAST_MAC,
    enviar_quadro,
    validar_ipv4,
    validar_udp_local,
    decrementar_ttl,
    criar_icmp_erro,
    criar_echo_reply,
    criar_pacote_udp,
    processar_http_udp,
    pode_gerar_erro_icmp
)
from registro import registrar_descarte, inc_metrica


def construir_tabela_rotas(config: dict) -> list:
    rotas = []
    # 1. Redes conectadas (interfaces de dados)
    for nome_if, iface in config["interfaces"].items():
        if iface["gerencia"]:
            continue
        rede = ipaddress.ip_network(f"{iface['ip']}/{iface['prefixo']}", strict=False)
        rotas.append({
            "rede": rede,
            "via": None,
            "interface": nome_if,
            "conectada": True
        })

    # 2. Rotas estáticas
    for r in config["rotas"]:
        rede_dest = ipaddress.ip_network(r["prefixo"], strict=False)
        ip_via = ipaddress.ip_address(r["via"])

        # Descobre qual interface conectada contém o próximo salto (via)
        for cr in rotas:
            if cr["conectada"] and ip_via in cr["rede"]:
                rotas.append({
                    "rede": rede_dest,
                    "via": r["via"],
                    "interface": cr["interface"],
                    "conectada": False
                })
                break

    return rotas


def buscar_rota(tabela_rotas: list, dest_ip_str: str):
    ip_dest = ipaddress.ip_address(dest_ip_str)
    melhor = None

    for r in tabela_rotas:
        if ip_dest in r["rede"]:
            if melhor is None:
                melhor = r
            elif r["rede"].prefixlen > melhor["rede"].prefixlen:
                melhor = r
            elif r["rede"].prefixlen == melhor["rede"].prefixlen and r["conectada"] and not melhor["conectada"]:
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
        enviar_quadro(out_if, mac_dst, 0x0800, pacote_ip)
    else:
        tabela_arp.enfileirar(
            proximo_salto, out_if_name, pacote_ip,
            gerado_localmente, pacote_original, in_if_name, config
        )


def enviar_pacote_gerado(pacote_ip: bytes, in_if_name: str, config: dict, tabela_rotas: list, tabela_arp):
    """Envia pacotes criados pelo próprio roteador (Echo Reply, erros ICMP, respostas UDP)."""
    origem_str = socket.inet_ntoa(pacote_ip[12:16])
    destino_str = socket.inet_ntoa(pacote_ip[16:20])
    proto = pacote_ip[9]

    # Se responde a pacote que chegou pela gerência, sai direto por ela sem consultar rotas (Seção 6)
    if config["interfaces"][in_if_name]["gerencia"]:
        enviar_ip(pacote_ip, in_if_name, destino_str, config, tabela_arp, gerado_localmente=True)
        return

    rota = buscar_rota(tabela_rotas, destino_str)
    if rota is not None:
        out_if_name, prox = rota
        enviar_ip(pacote_ip, out_if_name, prox, config, tabela_arp, gerado_localmente=True)
    else:
        registrar_descarte("sem_rota", origem_str, destino_str, proto)


def tratar_falha_arp_icmp(pacote_original: bytes, in_if_name: str, config: dict, tabela_rotas: list, tabela_arp):
    if not pode_gerar_erro_icmp(pacote_original, False, config["interfaces"]):
        return
    ip_origem_icmp = config["interfaces"][in_if_name]["ip"]
    icmp_erro = criar_icmp_erro(3, 1, pacote_original, ip_origem_icmp)
    enviar_pacote_gerado(icmp_erro, in_if_name, config, tabela_rotas, tabela_arp)


def verificar_filtros(pacote_ip: bytes, filtros: list):
    """Retorna ('permitir', None) ou ('negar', indice_regra) conforme Seção 11."""
    ihl = (pacote_ip[0] & 0x0F) * 4
    proto_num = pacote_ip[9]
    ip_orig = ipaddress.ip_address(socket.inet_ntoa(pacote_ip[12:16]))
    ip_dest = ipaddress.ip_address(socket.inet_ntoa(pacote_ip[16:20]))

    flags_desloc = struct.unpack("!H", pacote_ip[6:8])[0]
    eh_fragmento_posterior = (flags_desloc & 0x1FFF) != 0
    dados_transporte = pacote_ip[ihl:]

    for idx, regra in enumerate(filtros, start=1):
        if regra["protocolo"] == "icmp" and proto_num != 1:
            continue
        if regra["protocolo"] == "udp" and proto_num != 17:
            continue

        if regra["origem"] != "*" and ip_orig not in ipaddress.ip_network(regra["origem"], strict=False):
            continue
        if regra["destino"] != "*" and ip_dest not in ipaddress.ip_network(regra["destino"], strict=False):
            continue

        if regra["porta"] != "*":
            if proto_num != 17 or eh_fragmento_posterior or len(dados_transporte) < 4:
                continue
            porta_dst = struct.unpack("!H", dados_transporte[2:4])[0]
            if porta_dst != int(regra["porta"]):
                continue

        return regra["acao"], idx

    return "permitir", None


def processar_ipv4(quadro: bytes, in_if_name: str, config: dict, tabela_rotas: list, tabela_arp):
    # Passo 1: Validação
    pacote_ip = validar_ipv4(quadro[14:])
    if pacote_ip is None:
        registrar_descarte("cabecalho")
        return

    origem_ip = socket.inet_ntoa(pacote_ip[12:16])
    dest_ip = socket.inet_ntoa(pacote_ip[16:20])
    proto = pacote_ip[9]
    ttl = pacote_ip[8]
    chegou_em_broadcast = (quadro[:6] == BROADCAST_MAC)

    # Passo 2: Broadcast e Multicast
    if dest_ip == "255.255.255.255" or (224 <= pacote_ip[16] <= 239):
        registrar_descarte("local", origem_ip, dest_ip, proto)
        return

    for if_info in config["interfaces"].values():
        if dest_ip == if_info["broadcast"]:
            registrar_descarte("local", origem_ip, dest_ip, proto)
            return

    # Passo 3: Entrega local (Seção 8)
    ips_locais = {info["ip"]: info for info in config["interfaces"].values()}
    if dest_ip in ips_locais:
        dst_if = ips_locais[dest_ip]
        in_if = config["interfaces"][in_if_name]
        ihl = (pacote_ip[0] & 0x0F) * 4

        # Antes da tabela: valida cabeçalho ICMP ou UDP (Seção 8)
        if proto == 1:
            dados_icmp = pacote_ip[ihl:]
            if len(dados_icmp) < 8:
                registrar_descarte("cabecalho")
                return
            if dados_icmp[0] == 8 and dados_icmp[1] == 0:
                from protocolos import checksum
                if checksum(dados_icmp) != 0:
                    registrar_descarte("cabecalho")
                    return
        elif proto == 17:
            info_udp = validar_udp_local(pacote_ip)
            if info_udp is None:
                registrar_descarte("cabecalho")
                return

        # Linha 1 da tabela: cruzamento entre dados e gerência
        if dst_if["gerencia"] != in_if["gerencia"]:
            registrar_descarte("local", origem_ip, dest_ip, proto)
            return

        # Linha 2 da tabela: ICMP Echo Request (8/0)
        if proto == 1 and pacote_ip[ihl] == 8 and pacote_ip[ihl + 1] == 0:
            res_icmp = criar_echo_reply(pacote_ip, dest_ip)
            enviar_pacote_gerado(res_icmp, in_if_name, config, tabela_rotas, tabela_arp)
            return

        # Linhas 3 e 4 da tabela: UDP
        if proto == 17:
            porta_orig, porta_dst, dados_app = info_udp
            if dst_if["gerencia"] and porta_dst == 9100:
                corpo_http = processar_http_udp(
                    dados_app,
                    tabela_arp.total_entradas(),
                    tabela_arp.total_pendentes()
                )
                pkt_resp = criar_pacote_udp(dest_ip, 9100, origem_ip, porta_orig, corpo_http)
                enviar_pacote_gerado(pkt_resp, in_if_name, config, tabela_rotas, tabela_arp)
                return

            registrar_descarte("local", origem_ip, dest_ip, proto)
            if pode_gerar_erro_icmp(pacote_ip, chegou_em_broadcast, config["interfaces"]):
                icmp_erro = criar_icmp_erro(3, 3, pacote_ip, dest_ip)
                enviar_pacote_gerado(icmp_erro, in_if_name, config, tabela_rotas, tabela_arp)
            return

        # Linha 5 da tabela: ICMP de outro tipo ou qualquer outro protocolo
        registrar_descarte("local", origem_ip, dest_ip, proto)
        return

    # Passo 4: Filtragem (Seção 11) e bloqueio de trânsito na gerência
    if config["interfaces"][in_if_name]["gerencia"]:
        registrar_descarte("local", origem_ip, dest_ip, proto)
        return

    acao, num_regra = verificar_filtros(pacote_ip, config["filtros"])
    if acao == "negar":
        registrar_descarte("filtro", origem_ip, dest_ip, proto, regra=num_regra)
        return

    # Passo 5: TTL
    if ttl <= 1:
        registrar_descarte("ttl", origem_ip, dest_ip, proto)
        if pode_gerar_erro_icmp(pacote_ip, chegou_em_broadcast, config["interfaces"]):
            ip_origem_icmp = config["interfaces"][in_if_name]["ip"]
            icmp_erro = criar_icmp_erro(11, 0, pacote_ip, ip_origem_icmp)
            enviar_pacote_gerado(icmp_erro, in_if_name, config, tabela_rotas, tabela_arp)
        return

    # Passo 6: Rota
    rota = buscar_rota(tabela_rotas, dest_ip)
    if rota is None:
        registrar_descarte("sem_rota", origem_ip, dest_ip, proto)
        if pode_gerar_erro_icmp(pacote_ip, chegou_em_broadcast, config["interfaces"]):
            ip_origem_icmp = config["interfaces"][in_if_name]["ip"]
            icmp_erro = criar_icmp_erro(3, 0, pacote_ip, ip_origem_icmp)
            enviar_pacote_gerado(icmp_erro, in_if_name, config, tabela_rotas, tabela_arp)
        return

    # Passo 7: Encaminhamento
    out_if_name, prox_salto = rota
    inc_metrica("pacotes_encaminhados")
    pacote_encaminhado = decrementar_ttl(pacote_ip)
    enviar_ip(
        pacote_encaminhado, out_if_name, prox_salto,
        config, tabela_arp, gerado_localmente=False,
        pacote_original=pacote_ip, in_if_name=in_if_name
    )