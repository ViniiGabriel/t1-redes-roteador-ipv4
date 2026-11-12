#!/usr/bin/env python3
import json
import time

METRICAS = {
    "quadros_recebidos_eth0": 0,
    "quadros_enviados_eth0": 0,
    "quadros_recebidos_eth1": 0,
    "quadros_enviados_eth1": 0,
    "quadros_recebidos_mgmt0": 0,
    "quadros_enviados_mgmt0": 0,
    "pacotes_encaminhados": 0,
    "icmp_gerados": 0,
    "respostas_http": 0,
    "descartes_quadro": 0,
    "descartes_cabecalho": 0,
    "descartes_ttl": 0,
    "descartes_sem_rota": 0,
    "descartes_arp": 0,
    "descartes_fila_arp": 0,
    "descartes_filtro": 0,
    "descartes_local": 0,
}


def inc_metrica(nome: str):
    if nome in METRICAS:
        METRICAS[nome] += 1


def gerar_corpo_prometheus(arp_entradas: int, arp_pendentes: int) -> bytes:
    ordem = [
        ("quadros_recebidos_eth0", "counter", METRICAS["quadros_recebidos_eth0"]),
        ("quadros_enviados_eth0", "counter", METRICAS["quadros_enviados_eth0"]),
        ("quadros_recebidos_eth1", "counter", METRICAS["quadros_recebidos_eth1"]),
        ("quadros_enviados_eth1", "counter", METRICAS["quadros_enviados_eth1"]),
        ("quadros_recebidos_mgmt0", "counter", METRICAS["quadros_recebidos_mgmt0"]),
        ("quadros_enviados_mgmt0", "counter", METRICAS["quadros_enviados_mgmt0"]),
        ("pacotes_encaminhados", "counter", METRICAS["pacotes_encaminhados"]),
        ("icmp_gerados", "counter", METRICAS["icmp_gerados"]),
        ("respostas_http", "counter", METRICAS["respostas_http"]),
        ("arp_entradas", "gauge", arp_entradas),
        ("arp_pendentes", "gauge", arp_pendentes),
        ("descartes_quadro", "counter", METRICAS["descartes_quadro"]),
        ("descartes_cabecalho", "counter", METRICAS["descartes_cabecalho"]),
        ("descartes_ttl", "counter", METRICAS["descartes_ttl"]),
        ("descartes_sem_rota", "counter", METRICAS["descartes_sem_rota"]),
        ("descartes_arp", "counter", METRICAS["descartes_arp"]),
        ("descartes_fila_arp", "counter", METRICAS["descartes_fila_arp"]),
        ("descartes_filtro", "counter", METRICAS["descartes_filtro"]),
        ("descartes_local", "counter", METRICAS["descartes_local"]),
    ]
    linhas = []
    for nome, tipo, valor in ordem:
        linhas.append(f"# TYPE {nome} {tipo}\n{nome} {valor}\n")
    return "".join(linhas).encode("utf-8")


def emitir_evento(dados: dict):
    t_str = f"{time.time():.3f}"
    partes = [f'"t": {t_str}']
    for k, v in dados.items():
        partes.append(f'{json.dumps(k)}: {json.dumps(v)}')
    print("{" + ", ".join(partes) + "}", flush=True)


def registrar_inicio(nome: str):
    emitir_evento({"evento": "inicio", "roteador": nome})


def registrar_arp_aprendido(ip: str, mac: str, interface: str):
    emitir_evento({"evento": "arp_aprendido", "ip": ip, "mac": mac, "interface": interface})


def registrar_arp_expirado(ip: str):
    emitir_evento({"evento": "arp_expirado", "ip": ip})


def registrar_arp_falhou(ip: str, interface: str):
    emitir_evento({"evento": "arp_falhou", "ip": ip, "interface": interface})


def registrar_descarte(motivo: str, origem: str = None, destino: str = None, protocolo: int = None, regra: int = None):
    inc_metrica(f"descartes_{motivo}")
    if motivo in ("quadro", "cabecalho"):
        return
    dados = {
        "evento": "descarte",
        "motivo": motivo,
        "origem": origem,
        "destino": destino,
        "protocolo": protocolo
    }
    if regra is not None:
        dados["regra"] = regra
    emitir_evento(dados)