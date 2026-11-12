#!/usr/bin/env python3
import sys
import socket
import ipaddress
import re


def erro_config(msg: str):
    sys.stderr.write(f"Erro na configuracao: {msg}\n")
    sys.exit(1)


def validar_ip_puro(ip_str: str) -> ipaddress.IPv4Address:
    partes = ip_str.split(".")
    if len(partes) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in partes):
        erro_config(f"IP invalido: {ip_str}")
    return ipaddress.IPv4Address(ip_str)


def validar_prefixo_estrito(cidr_str: str) -> ipaddress.IPv4Network:
    if "/" not in cidr_str:
        erro_config(f"Prefixo sem barra: {cidr_str}")
    ip_p, pref_p = cidr_str.split("/", 1)
    validar_ip_puro(ip_p)
    if not pref_p.isdigit() or not (0 <= int(pref_p) <= 32):
        erro_config(f"Tamanho de prefixo invalido: {cidr_str}")
    try:
        # strict=True recusa bits de host diferentes de zero (ex: 10.0.4.5/24)
        return ipaddress.IPv4Network(cidr_str, strict=True)
    except ValueError:
        erro_config(f"Prefixo possui bits de host nao zerados: {cidr_str}")


def ler_configuracao(caminho_arquivo):
    nome_roteador = None
    qtd_gerencia = 0
    qtd_dados = 0
    interfaces = {}
    macs_usados = set()
    redes_interfaces = []
    rotas = []
    prefixos_rotas = set()
    filtros = []

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            linhas = f.readlines()
    except Exception as e:
        erro_config(f"Nao foi possivel ler o arquivo: {e}")

    for linha in linhas:
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue

        partes = linha.split()
        diretiva = partes[0]

        if diretiva == "nome":
            if len(partes) != 2 or nome_roteador is not None:
                erro_config("Diretiva 'nome' invalida ou duplicada")
            nome_roteador = partes[1]

        elif diretiva in ("interface", "gerencia"):
            if len(partes) != 4:
                erro_config(f"Diretiva '{diretiva}' exige 4 campos")

            nome_if, cidr_str, mac_str = partes[1], partes[2], partes[3]

            if nome_if in interfaces:
                erro_config(f"Interface duplicada: {nome_if}")

            # MAC precisa ter 6 pares hexadecimais minúsculos
            if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac_str):
                erro_config(f"MAC invalido: {mac_str}")
            if mac_str in macs_usados:
                erro_config(f"MAC duplicado: {mac_str}")
            macs_usados.add(mac_str)

            if "/" not in cidr_str:
                erro_config(f"Endereco de interface sem prefixo: {cidr_str}")
            ip_str, pref_str = cidr_str.split("/", 1)
            ip_obj = validar_ip_puro(ip_str)
            if not pref_str.isdigit() or not (0 <= int(pref_str) <= 32):
                erro_config(f"Prefixo invalido: {cidr_str}")
            prefixo = int(pref_str)

            rede_obj = ipaddress.IPv4Network(f"{ip_str}/{prefixo}", strict=False)

            # Endereço da interface não pode ser endereço de rede nem de broadcast do próprio prefixo
            if ip_obj == rede_obj.network_address or ip_obj == rede_obj.broadcast_address:
                erro_config(f"IP da interface {ip_str} eh endereco de rede ou broadcast")

            # Nenhuma interface (incluindo gerência) pode ter rede sobreposta a outra
            for outra_rede in redes_interfaces:
                if rede_obj.overlaps(outra_rede):
                    erro_config(f"Redes sobrepostas: {rede_obj} e {outra_rede}")
            redes_interfaces.append(rede_obj)

            eh_ger = (diretiva == "gerencia")
            if eh_ger:
                qtd_gerencia += 1
            else:
                qtd_dados += 1

            interfaces[nome_if] = {
                "nome": nome_if,
                "ip": ip_str,
                "ip_obj": ip_obj,
                "prefixo": prefixo,
                "rede_obj": rede_obj,
                "ip_bytes": socket.inet_aton(ip_str),
                "mac": mac_str,
                "mac_bytes": bytes.fromhex(mac_str.replace(":", "")),
                "broadcast": str(rede_obj.broadcast_address),
                "gerencia": eh_ger
            }

        elif diretiva == "rota":
            if len(partes) != 4 or partes[2] != "via":
                erro_config("Diretiva 'rota' invalida")
            rede_rota = validar_prefixo_estrito(partes[1])
            via_ip = validar_ip_puro(partes[3])

            if partes[1] in prefixos_rotas:
                erro_config(f"Rota com prefixo duplicado: {partes[1]}")
            prefixos_rotas.add(partes[1])

            rotas.append({
                "prefixo": partes[1],
                "via": partes[3],
                "via_obj": via_ip
            })

        elif diretiva == "filtro":
            if len(partes) != 6:
                erro_config("Diretiva 'filtro' exige 6 campos")
            acao, proto, orig, dest, porta = partes[1], partes[2], partes[3], partes[4], partes[5]

            if acao not in ("permitir", "negar"):
                erro_config(f"Acao de filtro invalida: {acao}")
            if proto not in ("icmp", "udp", "*"):
                erro_config(f"Protocolo de filtro invalido: {proto}")
            if orig != "*":
                validar_prefixo_estrito(orig)
            if dest != "*":
                validar_prefixo_estrito(dest)

            if porta != "*":
                if proto != "udp":
                    erro_config("Porta numerica so eh permitida quando o protocolo for udp")
                if not porta.isdigit() or not (1 <= int(porta) <= 65535):
                    erro_config(f"Porta invalida: {porta}")

            filtros.append({
                "acao": acao,
                "protocolo": proto,
                "origem": orig,
                "destino": dest,
                "porta": porta
            })

        else:
            erro_config(f"Diretiva desconhecida: {diretiva}")

    # Validações globais de obrigatoriedade
    if nome_roteador is None or qtd_gerencia != 1 or qtd_dados < 1:
        erro_config("Faltam diretivas obrigatorias (nome, gerencia ou interface)")

    # Validação dos próximos saltos (via) das rotas
    ips_proprios = {info["ip_obj"] for info in interfaces.values()}
    redes_dados = [info["rede_obj"] for info in interfaces.values() if not info["gerencia"]]

    for r in rotas:
        via_obj = r["via_obj"]
        if via_obj in ips_proprios:
            erro_config(f"Proximo salto {via_obj} eh endereco do proprio roteador")
        if not any(via_obj in rede for rede in redes_dados):
            erro_config(f"Proximo salto {via_obj} nao pertence a nenhuma rede de dados conectada")

    return {
        "nome": nome_roteador,
        "interfaces": interfaces,
        "rotas": rotas,
        "filtros": filtros
    }