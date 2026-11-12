#!/usr/bin/env python3
import json
import time


def emitir_evento(dados: dict):
    t_str = f"{time.time():.3f}"
    partes = [f'"t": {t_str}']
    for k, v in dados.items():
        partes.append(f'{json.dumps(k)}: {json.dumps(v)}')
    linha = "{" + ", ".join(partes) + "}"
    print(linha, flush=True)


def registrar_inicio(nome: str):
    emitir_evento({
        "evento": "inicio",
        "roteador": nome
    })


def registrar_arp_aprendido(ip: str, mac: str, interface: str):
    emitir_evento({
        "evento": "arp_aprendido",
        "ip": ip,
        "mac": mac,
        "interface": interface
    })


def registrar_arp_expirado(ip: str):
    emitir_evento({
        "evento": "arp_expirado",
        "ip": ip
    })


def registrar_arp_falhou(ip: str, interface: str):
    emitir_evento({
        "evento": "arp_falhou",
        "ip": ip,
        "interface": interface
    })


def registrar_descarte(motivo: str, origem: str, destino: str, protocolo: int, regra: int = None):
    # 'quadro' e 'cabecalho' não geram registros na saída padrão
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
