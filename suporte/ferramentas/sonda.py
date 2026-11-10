"""Sonda dos testes automáticos: roda dentro de h1, h2 ou gerente.

Recebe um objeto JSON no primeiro argumento e devolve outro na saída padrão.
Modos:
  quadros    envia quadros pela eth0 e captura o que chega nela
             {"modo": "quadros", "envios": [[atraso_s, "hex"], ...], "duracao": s}
  responder  responde, depois de um atraso, às requisições ARP por endereços falsos
             e captura o que chega na eth0
             {"modo": "responder", "falsos": {"10.0.4.96": "02:..."}, "atraso": s,
              "duracao": s, "max_respostas": n}
  udp        envia um datagrama UDP pela pilha do Linux e espera uma resposta
             {"modo": "udp", "destino": ip, "porta": n, "dados": "hex", "espera": s}
A captura ignora os quadros que a própria máquina enviou. Cada quadro capturado
vem com o instante absoluto de chegada, em segundos desde 1970.
"""
import json
import select
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1


def abrir(interface="eth0"):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    s.bind((interface, 0))
    indice = socket.if_nametoindex(interface)
    s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, struct.pack("iHH8s", indice, PACKET_MR_PROMISC, 0, b""))
    return s


def pronto():
    sys.stderr.write("pronto\n")
    sys.stderr.flush()


def modo_quadros(p):
    s = abrir()
    pronto()
    capturados = []
    envios = [(float(a), bytes.fromhex(h)) for a, h in p.get("envios", [])]
    inicio = time.time()
    fim = inicio + float(p["duracao"])
    enviados = []
    i = 0
    proximo = inicio + envios[0][0] if envios else None
    while True:
        agora = time.time()
        if proximo is not None and agora >= proximo:
            s.send(envios[i][1])
            enviados.append(agora)
            i += 1
            proximo = (proximo + envios[i][0]) if i < len(envios) else None
            continue
        if agora >= fim:
            break
        limite = fim if proximo is None else min(fim, proximo)
        r, _, _ = select.select([s], [], [], max(0.0, limite - agora))
        if r:
            dados, endereco = s.recvfrom(65535)
            if endereco[2] != PACKET_OUTGOING:
                capturados.append([time.time(), dados.hex()])
    return {"enviados": enviados, "capturados": capturados}


def modo_responder(p):
    s = abrir()
    pronto()
    falsos = {ip: bytes.fromhex(mac.replace(":", "")) for ip, mac in p["falsos"].items()}
    atraso = float(p.get("atraso", 0))
    restantes = int(p.get("max_respostas", 1000))
    capturados = []
    agendadas = []
    respostas = []
    fim = time.time() + float(p["duracao"])
    while True:
        agora = time.time()
        for item in [a for a in agendadas if a[0] <= agora]:
            agendadas.remove(item)
            s.send(item[1])
            respostas.append(agora)
        if agora >= fim:
            break
        limite = min([fim] + [a[0] for a in agendadas])
        r, _, _ = select.select([s], [], [], max(0.0, limite - agora))
        if not r:
            continue
        dados, endereco = s.recvfrom(65535)
        if endereco[2] == PACKET_OUTGOING:
            continue
        capturados.append([time.time(), dados.hex()])
        if len(dados) >= 42 and dados[12:14] == b"\x08\x06" and dados[20:22] == b"\x00\x01":
            alvo = socket.inet_ntoa(dados[38:42])
            if alvo in falsos and restantes > 0:
                restantes -= 1
                mac = falsos[alvo]
                arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac + dados[38:42] + dados[22:28] + dados[28:32]
                quadro = dados[22:28] + mac + b"\x08\x06" + arp
                quadro += b"\x00" * (60 - len(quadro))
                agendadas.append((time.time() + atraso, quadro))
    return {"capturados": capturados, "respostas": respostas}


def modo_udp(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    s.settimeout(float(p.get("espera", 2)))
    s.sendto(bytes.fromhex(p["dados"]), (p["destino"], int(p["porta"])))
    porta_local = s.getsockname()[1]
    try:
        dados, origem = s.recvfrom(65535)
    except socket.timeout:
        return {"porta_local": porta_local, "resposta": None}
    return {"porta_local": porta_local, "resposta": dados.hex(), "origem": [origem[0], origem[1]]}


def main():
    p = json.loads(sys.argv[1])
    modos = {"quadros": modo_quadros, "responder": modo_responder, "udp": modo_udp}
    print(json.dumps(modos[p["modo"]](p)))


main()
