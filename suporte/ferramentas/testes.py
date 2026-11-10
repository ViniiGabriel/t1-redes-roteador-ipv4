"""Testes automáticos do roteador: docker compose run --rm testes [PALAVRA ...]

Com palavras, roda só os testes cujo nome ou grupo contém alguma delas.
Cada teste verifica um comportamento da especificação, com os valores dela.
"""
import re
import struct
import sys
import threading
import time
import traceback

from comum import *  # noqa: F401,F403
import comum as c

H1, H2, GER = "10.0.1.10", "10.0.4.10", "192.168.100.100"


class Falhou(Exception):
    pass


def confere(condicao, mensagem):
    if not condicao:
        raise Falhou(mensagem)


# ------------------------------------------------------------------ montagem dos estímulos

def de_h1(pacote, destino_mac=None):
    return c.eth(destino_mac or c.MAC["r1.eth0"], c.MAC["h1"], 0x0800, pacote)


def de_h2(pacote, destino_mac=None):
    return c.eth(destino_mac or c.MAC["r3.eth1"], c.MAC["h2"], 0x0800, pacote)


def de_gerente(pacote, roteador="r1"):
    return c.eth(c.MAC[f"{roteador}.mgmt0"], c.MAC["gerente"], 0x0800, pacote)


def udp_ip(origem, destino, porta_destino, dados=b"teste", porta_origem=33000, ttl=64, ident=0x2222, **kw):
    return c.ipv4(origem, destino, 17, c.udp_seg(origem, destino, porta_origem, porta_destino, dados),
                  ttl=ttl, ident=ident, **kw)


def chegou_como(pacote, ttl):
    """O pacote com outro TTL e o checksum recalculado, como um roteador o encaminha."""
    ihl = (pacote[0] & 0x0F) * 4
    cab = bytearray(pacote[:ihl])
    cab[8] = ttl
    cab[10:12] = b"\x00\x00"
    cab[10:12] = struct.pack("!H", c.checksum(cab))
    return bytes(cab) + pacote[ihl:]


def trecho_original(pacote):
    ihl = (pacote[0] & 0x0F) * 4
    return pacote[:ihl + 8]


def confere_gerado(i, origem, destino, ttl_chegada, proto):
    confere(i["origem"] == origem, f"origem {i['origem']}, esperada {origem}")
    confere(i["destino"] == destino, f"destino {i['destino']}, esperado {destino}")
    confere(i["ihl"] == 20 and i["tos"] == 0 and i["id"] == 0 and i["frag"] == 0,
            f"cabeçalho gerado com IHL {i['ihl']}, tipo de serviço {i['tos']}, identificação {i['id']} "
            f"e flags/deslocamento {i['frag']}; esperados 20, 0, 0 e 0")
    confere(i["ttl"] == ttl_chegada, f"TTL {i['ttl']} na chegada, esperado {ttl_chegada} (64 na criação)")
    confere(i["proto"] == proto, f"protocolo {i['proto']}, esperado {proto}")
    confere(i["soma_ok"], "checksum do cabeçalho IPv4 não confere")


def confere_erro(m, tipo, codigo, origem, destino, ttl_chegada, original):
    confere((m["tipo"], m["codigo"]) == (tipo, codigo),
            f"mensagem {m['tipo']}/{m['codigo']}, esperada {tipo}/{codigo}")
    confere_gerado(m["ip"], origem, destino, ttl_chegada, 1)
    confere(m["soma_ok"], "checksum ICMP não confere")
    confere(m["resto"] == b"\x00\x00\x00\x00", f"4 bytes depois do checksum: {m['resto'].hex()}, esperados zeros")
    esperado = trecho_original(original)
    confere(m["corpo"] == esperado,
            f"conteúdo da mensagem de erro:\n            obtido   {m['corpo'].hex()}\n"
            f"            esperado {esperado.hex()} (cabeçalho original como chegou ao roteador e 8 bytes)")


def ping(origem, destino, *extra, tempo=30):
    r = c.executar(origem, "ping", "-n", *extra, destino, tempo=tempo)
    return r.stdout + r.stderr


def respostas_ping(saida, de):
    return [int(m.group(1)) for m in re.finditer(rf"bytes from {re.escape(de)}: icmp_seq=\d+ ttl=(\d+)", saida)]


def resumo(saida):
    linhas = [l for l in saida.strip().splitlines() if l.strip()]
    return "\n            ".join(linhas[:8])


def nada_de_ip(capt, origem_mac=None):
    lista = [q for q in c.quadros(capt) if q.eh_ip() and (origem_mac is None or q.origem == origem_mac)]
    return lista


def arps_de(capt, mac):
    return [q for q in c.quadros(capt) if q.eh_arp() and q.origem == mac]


def delta(antes, depois, chave):
    return depois.get(chave, 0) - antes.get(chave, 0)


def exige_metricas(r):
    m = c.metricas(r)
    confere(m is not None, f"{r} não respondeu GET /metrics com 200 OK")
    return m


# ------------------------------------------------------------------ registro dos testes

TESTES = []
GRUPOS = []


def grupo(titulo, confs=None):
    GRUPOS.append((titulo, confs or {}))


def teste(nome):
    def registrar(f):
        TESTES.append((len(GRUPOS) - 1, nome, f))
        return f
    return registrar


CONTEXTO = {}


# ================================================================== Ethernet e ARP

grupo("1. Ambiente, Ethernet e resposta ARP")


@teste("Registro inicio de r1, r2 e r3 como primeira linha da saída padrão")
def _():
    for r in c.ROTEADORES:
        objs, brutas = c.registros(r, CONTEXTO["reinicio"])
        confere(objs, f"{r}: nenhuma linha JSON na saída padrão depois do início")
        obj, linha = objs[0]
        confere(obj.get("evento") == "inicio", f"{r}: a primeira linha é {linha}")
        confere(list(obj) == ["t", "evento", "roteador"], f"{r}: campos {list(obj)}, esperados t, evento, roteador")
        confere(obj["roteador"] == r, f"{r}: roteador {obj['roteador']!r}, esperado {r!r}")
        confere(re.search(r'"t"\s*:\s*\d+\.\d{3}\s*,', linha), f"{r}: t sem três casas decimais em {linha}")


@teste("Resposta ARP à requisição de h1")
def _():
    req = c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(1, c.MAC["h1"], H1, "00:00:00:00:00:00", "10.0.1.1"))
    _, capt = c.enviar("h1", [req], duracao=1.0)
    # O Linux de h1 também pode sondar r1 nesse instante; vale a resposta à requisição do teste.
    resp = [q for q in arps_de(capt, c.MAC["r1.eth0"])]
    confere(resp, "nenhum quadro ARP de r1")
    q = resp[0]
    a = q.arp()
    confere(q.destino == c.MAC["h1"], f"destino Ethernet {q.destino}, esperado {c.MAC['h1']} (unicast)")
    confere(a["cab"] == (1, 0x0800, 6, 4), f"hardware, protocolo e tamanhos {a['cab']}")
    confere(a["op"] == 2, f"operação {a['op']}, esperada 2")
    confere((a["sha"], a["spa"]) == (c.MAC["r1.eth0"], "10.0.1.1"), f"remetente {a['sha']} {a['spa']}")
    confere((a["tha"], a["tpa"]) == (c.MAC["h1"], H1), f"alvo {a['tha']} {a['tpa']}")
    confere(len(q.b) == 60, f"quadro de {len(q.b)} bytes, esperado 60 (completado com zeros)")
    confere(q.b[42:] == b"\x00" * 18, "o preenchimento depois da mensagem ARP não é de zeros")


@teste("Resposta ARP vai ao endereço físico do remetente da mensagem ARP")
def _():
    falso = "02:00:00:00:0a:31"
    req = c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(1, falso, "10.0.1.31", "00:00:00:00:00:00", "10.0.1.1"))
    _, capt = c.enviar("h1", [req], duracao=1.0)
    resp = arps_de(capt, c.MAC["r1.eth0"])
    confere(len(resp) == 1, f"{len(resp)} quadros ARP de r1, esperado 1")
    a = resp[0].arp()
    confere(resp[0].destino == falso, f"destino Ethernet {resp[0].destino}, esperado {falso}")
    confere((a["tha"], a["tpa"]) == (falso, "10.0.1.31"), f"alvo {a['tha']} {a['tpa']}")


@teste("Mensagens ARP ignoradas: alvo de outro endereço e remetente 0.0.0.0")
def _():
    outro = c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(1, c.MAC["h1"], H1, "00:00:00:00:00:00", "10.0.1.77"))
    sonda = c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(1, c.MAC["h1"], "0.0.0.0", "00:00:00:00:00:00", "10.0.1.1"))
    _, capt = c.enviar("h1", [outro, sonda], duracao=1.0, intervalo=0.1)
    resp = arps_de(capt, c.MAC["r1.eth0"])
    confere(not resp, f"r1 respondeu {len(resp)} vez(es); nenhuma resposta esperada")


@teste("Quadros descartados: outro destino, EtherType não tratado e ARP fora do formato")
def _():
    eco = c.ipv4(H1, "10.0.1.1", 1, c.echo(0x51, 1, b"x"))
    estimulos = [
        c.eth("02:00:00:00:01:99", c.MAC["h1"], 0x0800, eco),
        c.eth(c.MAC["r1.eth0"], c.MAC["h1"], 0x86DD, eco),
        c.eth(c.MAC["r1.eth0"], c.MAC["h1"], 0x8100, eco),
        c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(1, c.MAC["h1"], H1, "00:00:00:00:00:00", "10.0.1.1", htype=6)),
        c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(1, c.MAC["h1"], H1, "00:00:00:00:00:00", "10.0.1.1")[:27]),
        c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(3, c.MAC["h1"], H1, "00:00:00:00:00:00", "10.0.1.1")),
    ]
    _, capt = c.enviar("h1", estimulos, duracao=1.0, intervalo=0.05)
    resp = [q for q in c.quadros(capt) if q.origem == c.MAC["r1.eth0"]]
    confere(not resp, f"r1 enviou {len(resp)} quadro(s); nenhum esperado")


@teste("Rede de gerência compartilhada: só o dono do endereço responde ao ARP")
def _():
    req = c.eth(c.BROADCAST, c.MAC["gerente"], 0x0806,
                c.arp(1, c.MAC["gerente"], GER, "00:00:00:00:00:00", "192.168.100.2"))
    _, capt = c.enviar("gerente", [req], duracao=1.0)
    resp = [q for q in c.quadros(capt) if q.eh_arp() and q.arp()["op"] == 2]
    origens = sorted(q.origem for q in resp)
    confere(origens == [c.MAC["r2.mgmt0"]], f"respostas de {origens or 'ninguém'}; esperada só de r2 ({c.MAC['r2.mgmt0']})")
    a = resp[0].arp()
    confere(a["spa"] == "192.168.100.2" and a["tpa"] == GER, f"resposta com remetente {a['spa']} e alvo {a['tpa']}")


# ================================================================== encaminhamento e ICMP

grupo("2. Requisição ARP, encaminhamento, TTL, checksum e ICMP")


@teste("ping de h1 a h2: três respostas com ttl=61")
def _():
    saida = ping("h1", H2, "-c", "3", "-W", "2")
    ttls = respostas_ping(saida, H2)
    confere(ttls == [61, 61, 61], f"respostas com TTL {ttls}; esperadas três com 61\n            {resumo(saida)}")


@teste("ping de h1 a 10.0.23.3: r3 responde com ttl=62")
def _():
    saida = ping("h1", "10.0.23.3", "-c", "3", "-W", "2")
    ttls = respostas_ping(saida, "10.0.23.3")
    confere(ttls == [62, 62, 62], f"respostas com TTL {ttls}; esperadas três com 62\n            {resumo(saida)}")


@teste("traceroute -n de h1 a h2: quatro saltos")
def _():
    r = c.executar("h1", "traceroute", "-n", "-w", "2", H2, tempo=90)
    saltos = []
    for linha in r.stdout.splitlines()[1:]:
        ips = re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", linha)
        saltos.append(ips[0] if ips else "*")
    esperado = ["10.0.1.1", "10.0.12.2", "10.0.23.3", H2]
    confere(saltos == esperado, f"saltos {saltos}; esperados {esperado}\n            {resumo(r.stdout)}")


@teste("Resposta de echo: identificador, sequência, dados e cabeçalho gerado")
def _():
    dados = bytes(range(37))
    _, capt = c.enviar("h1", [de_h1(c.ipv4(H1, "10.0.1.1", 1, c.echo(0x1234, 7, dados)))], duracao=1.0)
    resp = c.icmps(capt, (0, 0), "10.0.1.1")
    confere(len(resp) == 1, f"{len(resp)} respostas de echo de 10.0.1.1, esperada 1")
    q, m = resp[0]
    confere_gerado(m["ip"], "10.0.1.1", H1, 64, 1)
    confere(m["soma_ok"], "checksum ICMP não confere")
    confere(m["resto"] == struct.pack("!HH", 0x1234, 7), f"identificador e sequência {m['resto'].hex()}, esperados 12340007")
    confere(m["corpo"] == dados, "os dados da resposta diferem dos da requisição")
    confere(q.origem == c.MAC["r1.eth0"] and q.destino == c.MAC["h1"], f"quadro de {q.origem} para {q.destino}")


@teste("Preenchimento ignorado na recepção e completado com zeros no envio")
def _():
    pacote = c.ipv4(H1, "10.0.1.1", 1, c.echo(0x77, 1))
    quadro = de_h1(pacote) + b"\xaa" * 18
    _, capt = c.enviar("h1", [quadro], duracao=1.0)
    resp = c.icmps(capt, (0, 0), "10.0.1.1")
    confere(len(resp) == 1, f"{len(resp)} respostas de echo, esperada 1")
    q, m = resp[0]
    confere(m["ip"]["total"] == 28, f"tamanho total {m['ip']['total']}, esperado 28: o preenchimento entrou nos dados")
    confere(m["soma_ok"], "checksum ICMP não confere")
    confere(len(q.b) == 60 and q.b[42:] == b"\x00" * 18, f"quadro de {len(q.b)} bytes; esperado 60, completado com zeros")


@teste("Encaminhamento: TTL menos 1 por roteador, checksum refeito, demais campos e opções intactos")
def _():
    pacote = udp_ip(H1, H2, 9, b"conteudo-preservado", ident=0x7777, tos=0x28, flags_desloc=0x4000,
                    opcoes=b"\x01\x01\x01\x00")
    cap = c.capturar("h2", 1.5)
    c.enviar("h1", [de_h1(pacote)], duracao=0.3)
    chegou = [q for q in c.quadros(c.capturados(cap)) if q.eh_ip() and q.ip()["id"] == 0x7777]
    confere(len(chegou) == 1, f"{len(chegou)} pacotes chegaram a h2, esperado 1")
    q = chegou[0]
    esperado = chegou_como(pacote, 61)
    confere(q.ip()["pacote"] == esperado, f"pacote em h2:\n            obtido   {q.ip()['pacote'].hex()}\n"
                                          f"            esperado {esperado.hex()}")
    confere(q.origem == c.MAC["r3.eth1"] and q.destino == c.MAC["h2"], f"quadro de {q.origem} para {q.destino}")


@teste("Encaminhamento de outros protocolos e de fragmentos")
def _():
    estimulos = [
        c.ipv4(H1, H2, 6, b"\x9c\x40\x00\x50" + bytes(16), ident=0x6001),
        udp_ip(H1, H2, 9, b"primeiro-fragmento", ident=0x6002, flags_desloc=0x2000),
        c.ipv4(H1, H2, 17, b"fragmento-do-meio", ident=0x6003, flags_desloc=0x2000 | 185),
    ]
    cap = c.capturar("h2", 1.5)
    c.enviar("h1", [de_h1(p) for p in estimulos], duracao=0.3, intervalo=0.05)
    ids = sorted(q.ip()["id"] for q in c.quadros(c.capturados(cap)) if q.eh_ip() and q.ip()["id"] in (0x6001, 0x6002, 0x6003))
    confere(ids == [0x6001, 0x6002, 0x6003], f"chegaram a h2 {[hex(i) for i in ids]}; esperados TCP, primeiro fragmento e fragmento do meio")


@teste("Validação do IPv4: pacotes malformados não são encaminhados nem respondidos")
def _():
    bom = udp_ip(H1, H2, 9, b"malformado", ident=0x5000)
    estimulos = [
        udp_ip(H1, H2, 9, b"checksum", ident=0x5001, soma=0x1234),
        udp_ip(H1, H2, 9, b"versao", ident=0x5002, versao=6),
        udp_ip(H1, H2, 9, b"ihl", ident=0x5003, ihl=4),
        udp_ip(H1, H2, 9, b"total-maior", ident=0x5004, total=200),
        udp_ip(H1, H2, 9, b"total-menor", ident=0x5005, total=19),
        bom[:19],
    ]
    cap = c.capturar("h2", 1.5)
    _, capt = c.enviar("h1", [de_h1(p) for p in estimulos], duracao=1.2, intervalo=0.05)
    chegaram = [q for q in c.quadros(c.capturados(cap)) if q.eh_ip() and 0x5000 <= q.ip()["id"] <= 0x5005]
    confere(not chegaram, f"{len(chegaram)} pacote(s) malformado(s) chegaram a h2")
    resp = c.icmps(capt)
    confere(not resp, f"h1 recebeu {len(resp)} mensagem(ns) ICMP; nenhuma esperada")


@teste("Time exceeded 11/0 de r2: origem, conteúdo e cabeçalho original como chegou")
def _():
    pacote = udp_ip(H1, H2, 33500, b"ttl", ttl=2, ident=0x4242)
    _, capt = c.enviar("h1", [de_h1(pacote)], duracao=1.0)
    resp = c.icmps(capt, (11, 0))
    confere(len(resp) == 1, f"{len(resp)} mensagens 11/0, esperada 1")
    confere_erro(resp[0][1], 11, 0, "10.0.12.2", H1, 63, chegou_como(pacote, 1))


@teste("Time exceeded 11/0 de r1 para TTL 1")
def _():
    saida = ping("h1", H2, "-c", "1", "-t", "1", "-W", "2")
    confere(re.search(r"From 10\.0\.1\.1 .*Time to live exceeded", saida), f"esperado From 10.0.1.1 ... Time to live exceeded\n            {resumo(saida)}")


@teste("Destino inalcançável 3/0 sem rota")
def _():
    pacote = c.ipv4(H1, "10.0.9.9", 1, c.echo(0x99, 1, b"sem-rota"))
    _, capt = c.enviar("h1", [de_h1(pacote)], duracao=1.0)
    resp = c.icmps(capt, (3, 0))
    confere(len(resp) == 1, f"{len(resp)} mensagens 3/0, esperada 1")
    confere_erro(resp[0][1], 3, 0, "10.0.1.1", H1, 64, pacote)


# ================================================================== ARP, 3/1, 3/3 e UDP

grupo("3. Expiração e fila do ARP, falha de resolução, 3/1, 3/3 e UDP local")


@teste("Expiração do cache ARP: nova requisição depois de 30 s (roda em paralelo)")
def _():
    # Começa agora e termina no fim do grupo, para não somar 32 s ao tempo dos testes.
    falso_ip, falso_mac = "10.0.4.95", "02:00:00:00:0a:95"
    resp = c.Sonda("h2", {"modo": "responder", "falsos": {falso_ip: falso_mac}, "atraso": 0,
                          "duracao": 34.0, "max_respostas": 3})
    envios = [[0.0, de_h1(udp_ip(H1, falso_ip, 9, b"a", ident=0x9501)).hex()],
              [20.0, de_h1(udp_ip(H1, falso_ip, 9, b"b", ident=0x9502)).hex()],
              [11.5, de_h1(udp_ip(H1, falso_ip, 9, b"c", ident=0x9503)).hex()]]
    remetente = c.Sonda("h1", {"modo": "quadros", "envios": envios, "duracao": 32.5})

    def concluir():
        enviados = remetente.resultado()["enviados"]
        r = resp.resultado()
        capt = c.quadros([(t, bytes.fromhex(h)) for t, h in r["capturados"]])
        reqs = [q.t for q in capt if q.eh_arp() and q.arp()["op"] == 1 and q.arp()["tpa"] == falso_ip]
        entregues = [q.ip()["id"] for q in capt if q.eh_ip() and q.destino == falso_mac]
        CONTEXTO["expiracao"] = r["respostas"][0] if r["respostas"] else None
        confere(len(enviados) == 3, "a sonda não enviou os três pacotes")
        confere(entregues == [0x9501, 0x9502, 0x9503], f"pacotes entregues ao endereço falso: {[hex(i) for i in entregues]}")
        rel = [round(t - enviados[0], 1) for t in reqs]
        confere(len(reqs) == 2, f"requisições ARP por {falso_ip} em {rel} s; esperadas 2: no primeiro pacote e "
                                f"no terceiro, 31,5 s depois, com a entrada já expirada; nenhuma no segundo, aos 20 s")
        confere(reqs[1] >= enviados[2] - 0.05, f"segunda requisição aos {rel[1]} s, antes do terceiro pacote")
    return concluir


@teste("Requisição ARP do roteador, repetida 1 s e 2 s depois, e 3/1 aos 3 s")
def _():
    pacote = udp_ip(H1, "10.0.4.98", 50000, b"sem-vizinho", ident=0x9801)
    cap = c.capturar("h2", 4.5)
    enviados, capt = c.enviar("h1", [de_h1(pacote)], duracao=4.5)
    reqs = [q for q in arps_de(c.capturados(cap), c.MAC["r3.eth1"]) if q.arp()["tpa"] == "10.0.4.98"]
    confere(len(reqs) == 3, f"{len(reqs)} requisições ARP de r3 por 10.0.4.98, esperadas 3")
    for q in reqs:
        a = q.arp()
        confere(q.destino == c.BROADCAST, f"requisição para {q.destino}, esperado broadcast")
        confere(a["op"] == 1 and a["cab"] == (1, 0x0800, 6, 4), f"operação {a['op']} e cabeçalho {a['cab']}")
        confere((a["sha"], a["spa"]) == (c.MAC["r3.eth1"], "10.0.4.1"), f"remetente {a['sha']} {a['spa']}")
        confere(a["tha"] == "00:00:00:00:00:00", f"endereço físico alvo {a['tha']}, esperado zeros")
        confere(len(q.b) == 60, f"quadro de {len(q.b)} bytes, esperado 60")
    t0 = reqs[0].t
    rel = [round(q.t - t0, 2) for q in reqs]
    confere(abs(rel[1] - 1.0) <= 0.3 and abs(rel[2] - 2.0) <= 0.3, f"requisições em {rel} s; esperadas em 0, 1 e 2 s")
    resp = c.icmps(capt, (3, 1))
    confere(len(resp) == 1, f"{len(resp)} mensagens 3/1 em h1, esperada 1")
    q, m = resp[0]
    atraso = q.t - t0
    confere(2.7 <= atraso <= 3.7, f"3/1 chegou {atraso:.2f} s depois da primeira requisição; esperado cerca de 3 s")
    confere_erro(m, 3, 1, "10.0.23.3", H1, 62, chegou_como(pacote, 62))


@teste("Fila de 16 pacotes por próximo salto em resolução")
def _():
    estimulos = [de_h1(udp_ip(H1, "10.0.4.97", 40000 + i, b"fila", ident=0x9700 + i)) for i in range(20)]
    cap = c.capturar("h2", 4.5)
    _, capt = c.enviar("h1", estimulos, duracao=4.5, intervalo=0.002)
    reqs = [q for q in arps_de(c.capturados(cap), c.MAC["r3.eth1"]) if q.arp()["tpa"] == "10.0.4.97"]
    confere(len(reqs) == 3, f"{len(reqs)} requisições ARP por 10.0.4.97; esperadas 3, uma resolução para a fila toda")
    portas = [struct.unpack("!H", m["corpo"][(m["corpo"][0] & 0x0F) * 4 + 2:(m["corpo"][0] & 0x0F) * 4 + 4])[0]
              for _, m in c.icmps(capt, (3, 1))]
    confere(portas == list(range(40000, 40016)),
            f"{len(portas)} mensagens 3/1, para as portas {portas[:3]}...; esperadas 16, para os 16 primeiros pacotes, na ordem")


@teste("Fila liberada na ordem de chegada quando a resposta ARP chega")
def _():
    falso_ip, falso_mac = "10.0.4.96", "02:00:00:00:0a:96"
    resp = c.Sonda("h2", {"modo": "responder", "falsos": {falso_ip: falso_mac}, "atraso": 1.3, "duracao": 3.5})
    estimulos = [de_h1(udp_ip(H1, falso_ip, 41000 + i, b"ordem", ident=0x9600 + i)) for i in range(5)]
    _, capt = c.enviar("h1", estimulos, duracao=3.5, intervalo=0.1)
    r = resp.resultado()
    capt2 = c.quadros([(t, bytes.fromhex(h)) for t, h in r["capturados"]])
    entregues = [q.ip()["id"] - 0x9600 for q in capt2 if q.eh_ip() and q.destino == falso_mac]
    confere(entregues == [0, 1, 2, 3, 4], f"pacotes entregues na ordem {entregues}; esperados 0, 1, 2, 3 e 4")
    reqs = [q for q in capt2 if q.eh_arp() and q.arp()["op"] == 1 and q.arp()["tpa"] == falso_ip]
    confere(len(reqs) == 2, f"{len(reqs)} requisições ARP; esperadas 2: a primeira e a repetição de 1 s, antes da resposta em 1,3 s")
    confere(not c.icmps(capt, (3, 1)), "h1 recebeu 3/1, mas a resolução teve sucesso")


@teste("Destino inalcançável 3/3 para UDP a uma porta sem serviço no roteador")
def _():
    pacote = udp_ip(H1, "10.0.4.1", 5555, b"porta")
    _, capt = c.enviar("h1", [de_h1(pacote)], duracao=1.0)
    resp = c.icmps(capt, (3, 3))
    confere(len(resp) == 1, f"{len(resp)} mensagens 3/3, esperada 1")
    confere_erro(resp[0][1], 3, 3, "10.0.4.1", H1, 62, chegou_como(pacote, 62))


@teste("Porta 9100 num endereço de dados também gera 3/3")
def _():
    pacote = udp_ip(H1, "10.0.1.1", 9100, b"GET /metrics HTTP/1.1\r\n\r\n")
    _, capt = c.enviar("h1", [de_h1(pacote)], duracao=1.0)
    resp = c.icmps(capt, (3, 3))
    confere(len(resp) == 1, f"{len(resp)} mensagens 3/3, esperada 1")
    confere_erro(resp[0][1], 3, 3, "10.0.1.1", H1, 64, pacote)


@teste("UDP local: checksum zero aceito; checksum errado e tamanho inválido descartados")
def _():
    def seg(porta, **kw):
        return c.ipv4(H1, "10.0.1.1", 17, c.udp_seg(H1, "10.0.1.1", 33000, porta, b"udp-local", **kw))
    estimulos = [seg(5556, soma=None), seg(5557, soma=0x1234), seg(5558, tamanho=7), seg(5559, tamanho=200)]
    _, capt = c.enviar("h1", [de_h1(p) for p in estimulos], duracao=1.0, intervalo=0.05)
    portas = []
    for _, m in c.icmps(capt, (3, 3)):
        portas.append(struct.unpack("!H", m["corpo"][22:24])[0])
    confere(portas == [5556], f"3/3 para as portas {portas}; esperado só para 5556, a de checksum zero")


@teste("Nenhuma mensagem de erro sobre erro ICMP, fragmento, broadcast ou origem inválida")
def _():
    erro = c.icmp(11, 0, bytes(4) + udp_ip(H2, H1, 9)[:28])
    estimulos = [
        de_h1(c.ipv4(H1, "10.0.9.9", 1, erro)),
        de_h1(c.ipv4(H1, "10.0.9.9", 17, b"meio-do-pacote", flags_desloc=100)),
        de_h1(udp_ip(H1, "10.0.9.9", 9), c.BROADCAST),
        de_h1(udp_ip("0.0.0.0", "10.0.9.9", 9)),
        de_h1(udp_ip("10.0.1.255", "10.0.9.9", 9)),
        de_h1(c.ipv4(H1, H2, 1, erro, ttl=1)),
    ]
    _, capt = c.enviar("h1", estimulos, duracao=1.2, intervalo=0.05)
    resp = c.icmps(capt)
    tipos = [f"{m['tipo']}/{m['codigo']} de {m['ip']['origem']}" for _, m in resp]
    confere(not resp, f"h1 recebeu {tipos}; nenhuma mensagem esperada")


@teste("Broadcast e multicast IPv4 descartados sem mensagem")
def _():
    estimulos = [de_h1(udp_ip(H1, d, 9)) for d in ("255.255.255.255", "10.0.1.255", "224.0.0.9", "192.168.100.255", "10.0.12.255")]
    cap = c.capturar("h2", 1.2)
    _, capt = c.enviar("h1", estimulos, duracao=1.2, intervalo=0.05)
    confere(not c.icmps(capt), "h1 recebeu mensagem ICMP; nenhuma esperada")
    confere(not nada_de_ip(c.capturados(cap), c.MAC["r3.eth1"]), "algum pacote chegou a h2")


@teste("Pacotes ao roteador que ele não atende: sem resposta")
def _():
    estimulos = [
        c.ipv4(H1, "192.168.100.1", 1, c.echo(0x61, 1)),
        c.ipv4(H1, "10.0.1.1", 1, c.icmp(13, 0, bytes(16))),
        c.ipv4(H1, "10.0.1.1", 6, b"\x9c\x40\x00\x50" + bytes(16)),
        c.ipv4(H1, "10.0.1.1", 1, c.echo(0x62, 1, b"errado", soma=0x1234)),
        c.ipv4(H1, "10.0.1.1", 1, c.icmp(8, 0, b"")),
    ]
    _, capt = c.enviar("h1", [de_h1(p) for p in estimulos], duracao=1.0, intervalo=0.05)
    resp = nada_de_ip(capt, c.MAC["r1.eth0"])
    confere(not resp, f"r1 enviou {len(resp)} pacote(s) a h1; nenhum esperado")


# ================================================================== gerência

grupo("4. HTTP sobre UDP, métricas e registros")


def http(caminho="/metrics", metodo="GET", versao="HTTP/1.1", bruto=None, roteador="r1"):
    req = bruto if bruto is not None else f"{metodo} {caminho} {versao}\r\nHost: {c.GERENCIA[roteador]}\r\n\r\n".encode()
    _, resp = c.udp("gerente", c.GERENCIA[roteador], 9100, req)
    return resp


@teste("GET /metrics: 200, cabeçalhos e as 19 métricas na ordem")
def _():
    resp = http()
    confere(resp is not None, "nenhuma resposta em 2 s")
    confere(len(resp) <= 1472, f"resposta de {len(resp)} bytes; o máximo é 1472")
    confere(b"\r\n\r\n" in resp, "resposta sem a linha vazia que separa cabeçalhos e corpo")
    cab, corpo = resp.split(b"\r\n\r\n", 1)
    linhas = cab.split(b"\r\n")
    confere(linhas[0] == b"HTTP/1.1 200 OK", f"linha de estado {linhas[0]!r}")
    confere(b"Content-Type: text/plain; version=0.0.4" in linhas[1:], f"cabeçalhos {linhas[1:]}")
    tam = [l for l in linhas[1:] if l.startswith(b"Content-Length: ")]
    confere(len(tam) == 1 and int(tam[0].split(b": ")[1]) == len(corpo),
            f"Content-Length {tam}; o corpo tem {len(corpo)} bytes")
    texto = corpo.decode()
    confere(texto.endswith("\n"), "a última linha do corpo não termina em \\n")
    ls = texto[:-1].split("\n")
    confere(len(ls) == 38, f"{len(ls)} linhas no corpo, esperadas 38")
    for i, (nome, tipo) in enumerate(c.METRICAS):
        confere(ls[2 * i] == f"# TYPE {nome} {tipo}", f"linha {2 * i + 1}: {ls[2 * i]!r}, esperada '# TYPE {nome} {tipo}'")
        confere(re.fullmatch(rf"{nome} \d+", ls[2 * i + 1]), f"linha {2 * i + 2}: {ls[2 * i + 1]!r}")


@teste("HTTP/1.0, 404, 501 e 400")
def _():
    casos = [
        (http(versao="HTTP/1.0"), b"HTTP/1.1 200 OK\r\n", "GET /metrics HTTP/1.0"),
        (http(caminho="/"), b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", "GET /"),
        (http(caminho="/metrics/"), b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", "GET /metrics/"),
        (http(metodo="POST"), b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n", "POST /metrics"),
        (http(metodo="HEAD", caminho="/x"), b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n", "HEAD /x"),
        (http(versao="HTTP/2.0"), b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", "versão HTTP/2.0"),
        (http(bruto=b"GET /metrics HTTP/1.1\r\n"), b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", "sem linha vazia"),
        (http(bruto=b"GET  /metrics HTTP/1.1\r\n\r\n"), b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", "dois espaços"),
        (http(bruto=b"GET /metrics\r\n\r\n"), b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", "dois campos"),
    ]
    for resp, esperado, nome in casos:
        confere(resp is not None, f"{nome}: nenhuma resposta")
        if esperado.endswith(b"\r\n\r\n"):
            confere(resp == esperado, f"{nome}: resposta {resp!r}, esperada {esperado!r}")
        else:
            confere(resp.startswith(esperado), f"{nome}: resposta começa por {resp[:40]!r}")


@teste("Resposta HTTP para o endereço e a porta de origem, com checksum UDP")
def _():
    req = b"GET /metrics HTTP/1.1\r\n\r\n"
    pacote = c.ipv4(GER, "192.168.100.1", 17, c.udp_seg(GER, "192.168.100.1", 45678, 9100, req))
    _, capt = c.enviar("gerente", [de_gerente(pacote)], duracao=1.0)
    resp = [q for q in c.quadros(capt) if q.eh_ip() and q.ip()["proto"] == 17 and q.ip()["origem"] == "192.168.100.1"]
    confere(len(resp) == 1, f"{len(resp)} respostas UDP de 192.168.100.1, esperada 1")
    i = resp[0].ip()
    confere_gerado(i, "192.168.100.1", GER, 64, 17)
    po, pd, tam, soma = struct.unpack("!HHHH", i["dados"][:8])
    confere((po, pd) == (9100, 45678), f"portas {po} → {pd}, esperadas 9100 → 45678")
    confere(tam == len(i["dados"]), f"tamanho UDP {tam}, os dados têm {len(i['dados'])} bytes")
    pseudo = c.ip_bytes("192.168.100.1") + c.ip_bytes(GER) + struct.pack("!BBH", 0, 17, tam)
    confere(soma != 0 and c.soma16(pseudo + i["dados"]) == 0xFFFF, "checksum UDP zero ou errado")


@teste("Contagem da própria consulta: entra a requisição, não a resposta")
def _():
    exige_metricas("r2")
    m1, m2 = exige_metricas("r2"), exige_metricas("r2")
    for chave in ("quadros_recebidos_mgmt0", "quadros_enviados_mgmt0", "respostas_http"):
        confere(delta(m1, m2, chave) == 1, f"{chave} variou {delta(m1, m2, chave)} entre duas consultas seguidas; esperado 1")


@teste("HTTP só pela interface de gerência")
def _():
    pacote = udp_ip(H1, "192.168.100.1", 9100, b"GET /metrics HTTP/1.1\r\n\r\n")
    _, capt = c.enviar("h1", [de_h1(pacote)], duracao=1.0)
    confere(not nada_de_ip(capt, c.MAC["r1.eth0"]), "r1 respondeu a h1")


@teste("O roteador não encaminha o que chega pela gerência")
def _():
    pacote = c.ipv4(GER, H2, 1, c.echo(0x63, 1))
    cap = c.capturar("h2", 1.0)
    _, capt = c.enviar("gerente", [de_gerente(pacote)], duracao=1.0)
    confere(not nada_de_ip(c.capturados(cap), c.MAC["r3.eth1"]), "o pacote chegou a h2")
    confere(not nada_de_ip(capt, c.MAC["r1.mgmt0"]), "r1 respondeu ao gerente")


@teste("ping do gerente a 192.168.100.2: ttl=64")
def _():
    saida = ping("gerente", "192.168.100.2", "-c", "3", "-W", "2")
    ttls = respostas_ping(saida, "192.168.100.2")
    confere(ttls == [64, 64, 64], f"respostas com TTL {ttls}\n            {resumo(saida)}")


@teste("Métricas de quadros: recebidos e enviados, sem contar os PACKET_OUTGOING")
def _():
    req = c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(1, c.MAC["h1"], H1, "00:00:00:00:00:00", "10.0.1.1"))
    m1 = exige_metricas("r1")
    c.enviar("h1", [req], duracao=0.5)
    m2 = exige_metricas("r1")
    confere(delta(m1, m2, "quadros_recebidos_eth0") == 1, f"quadros_recebidos_eth0 variou {delta(m1, m2, 'quadros_recebidos_eth0')}, esperado 1")
    confere(delta(m1, m2, "quadros_enviados_eth0") == 1, f"quadros_enviados_eth0 variou {delta(m1, m2, 'quadros_enviados_eth0')}, esperado 1")


def estimulos_de_descarte():
    """Um estímulo por motivo em r1; devolve (instante, métricas antes, métricas depois)."""
    eco = c.ipv4(H1, "10.0.1.1", 1, c.echo(0x71, 1))
    lista = [
        c.eth("02:00:00:00:01:99", c.MAC["h1"], 0x0800, eco),                                   # quadro
        c.eth(c.MAC["r1.eth0"], c.MAC["h1"], 0x86DD, eco),                                      # quadro
        c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(1, c.MAC["h1"], H1, "00:00:00:00:00:00", "10.0.1.1", htype=6)),
        c.eth(c.BROADCAST, c.MAC["h1"], 0x0806, c.arp(1, c.MAC["h1"], H1, "00:00:00:00:00:00", "10.0.1.77")),  # ignorado
        de_h1(udp_ip(H1, H2, 9, soma=0x1234)),                                                   # cabecalho
        de_h1(c.ipv4(H1, "10.0.1.1", 1, b"\x08\x00\x00\x00")),                                   # cabecalho
        de_h1(c.ipv4(H1, "10.0.1.1", 1, c.echo(0x72, 1, b"x", soma=0x1234))),                     # cabecalho
        de_h1(c.ipv4(H1, "10.0.1.1", 17, c.udp_seg(H1, "10.0.1.1", 1, 5555, b"x", soma=0x1234))),  # cabecalho
        de_h1(udp_ip(H1, H2, 9, ttl=1)),                                                         # ttl
        de_h1(c.ipv4(H1, "10.0.9.9", 1, c.echo(0x73, 1))),                                       # sem_rota
        de_h1(c.ipv4("10.0.77.7", "10.0.1.1", 1, c.echo(0x74, 1))),                              # sem_rota, gerado
        de_h1(c.ipv4(H1, "192.168.100.1", 1, c.echo(0x75, 1))),                                  # local
        de_h1(udp_ip(H1, "255.255.255.255", 9)),                                                 # local
        de_h1(c.ipv4(H1, "10.0.1.1", 1, c.icmp(13, 0, bytes(16)))),                              # local
        de_h1(udp_ip(H1, "10.0.1.1", 5555)),                                                     # local e 3/3
        de_h1(udp_ip(H1, H2, 53, b"dns")),                                                       # filtro
    ]
    if "descartes" not in CONTEXTO:
        m1 = c.metricas("r1")
        t0 = time.time()
        c.enviar("h1", lista, duracao=1.0, intervalo=0.05)
        CONTEXTO["descartes"] = (t0, m1, c.metricas("r1"), len(lista))
    return CONTEXTO["descartes"]


@teste("Métricas de descarte por motivo e mensagens geradas")
def _():
    t0, m1, m2, n = estimulos_de_descarte()
    confere(m1 is not None and m2 is not None, "r1 não respondeu GET /metrics com 200 OK")
    esperado = {"quadros_recebidos_eth0": n, "descartes_quadro": 3, "descartes_cabecalho": 4, "descartes_ttl": 1,
                "descartes_sem_rota": 2, "descartes_local": 4, "descartes_filtro": 1, "descartes_arp": 0,
                "descartes_fila_arp": 0, "pacotes_encaminhados": 0, "icmp_gerados": 4}
    erros = [f"{k}: {delta(m1, m2, k)} (esperado {v})" for k, v in esperado.items() if delta(m1, m2, k) != v]
    confere(not erros, "variações depois de um estímulo por motivo:\n            " + "\n            ".join(erros))


@teste("Registros de descarte: motivo, origem, destino, protocolo e regra")
def _():
    t0, _, _, _ = estimulos_de_descarte()
    objs, _ = c.registros("r1", t0)
    desc = [o for o, _ in objs if o.get("evento") == "descarte"]
    obtidos = sorted((o.get("motivo"), o.get("origem"), o.get("destino"), o.get("protocolo"), o.get("regra")) for o in desc)
    esperados = sorted([
        ("ttl", H1, H2, 17, None),
        ("sem_rota", H1, "10.0.9.9", 1, None),
        ("sem_rota", "10.0.1.1", "10.0.77.7", 1, None),
        ("local", H1, "192.168.100.1", 1, None),
        ("local", H1, "255.255.255.255", 17, None),
        ("local", H1, "10.0.1.1", 1, None),
        ("local", H1, "10.0.1.1", 17, None),
        ("filtro", H1, H2, 17, 1),
    ], key=str)
    confere(sorted(obtidos, key=str) == esperados,
            "registros obtidos:\n            " + "\n            ".join(map(str, sorted(obtidos, key=str))) +
            "\n            esperados:\n            " + "\n            ".join(map(str, esperados)))


@teste("Métricas: pacotes encaminhados e ICMP gerados num ping")
def _():
    antes = {r: exige_metricas(r) for r in c.ROTEADORES}
    ping("h1", H2, "-c", "3", "-W", "2")
    depois = {r: exige_metricas(r) for r in c.ROTEADORES}
    for r in c.ROTEADORES:
        d = delta(antes[r], depois[r], "pacotes_encaminhados")
        confere(d == 6, f"{r}: pacotes_encaminhados variou {d}; esperado 6, três requisições e três respostas")
        confere(delta(antes[r], depois[r], "icmp_gerados") == 0, f"{r}: icmp_gerados variou num ping que atravessa")


@teste("Métricas e registros da falha de ARP: arp_pendentes, fila_arp, arp e arp_falhou")
def _():
    estimulos = [de_h1(udp_ip(H1, "10.0.4.94", 42000 + i, ident=0x9400 + i)) for i in range(20)]
    m1 = exige_metricas("r3")
    t0 = time.time()
    c.enviar("h1", estimulos, duracao=0.3, intervalo=0.002)
    time.sleep(0.7)
    meio = exige_metricas("r3")
    time.sleep(3.0)
    m2 = exige_metricas("r3")
    confere(meio["arp_pendentes"] == 16, f"arp_pendentes {meio['arp_pendentes']} durante a resolução, esperado 16")
    confere(m2["arp_pendentes"] == 0, f"arp_pendentes {m2['arp_pendentes']} depois da falha, esperado 0")
    for k, v in (("descartes_fila_arp", 4), ("descartes_arp", 16), ("icmp_gerados", 16), ("pacotes_encaminhados", 20)):
        confere(delta(m1, m2, k) == v, f"{k} variou {delta(m1, m2, k)}, esperado {v}")
    objs, _ = c.registros("r3", t0)
    falhas = [o for o, _ in objs if o.get("evento") == "arp_falhou"]
    confere([(o.get("ip"), o.get("interface")) for o in falhas] == [("10.0.4.94", "eth1")],
            f"registros arp_falhou: {falhas}")
    motivos = sorted(o.get("motivo") for o, _ in objs if o.get("evento") == "descarte")
    confere(motivos == ["arp"] * 16 + ["fila_arp"] * 4, f"descartes registrados: {motivos.count('arp')} arp e {motivos.count('fila_arp')} fila_arp")


@teste("Registros arp_aprendido e arp_expirado, até 1 s depois dos 30 s")
def _():
    t = CONTEXTO.get("expiracao")
    confere(t is not None, "depende do teste de expiração do cache ARP, do grupo 3, que não rodou ou falhou")
    objs, _ = c.registros("r3", t - 1)
    apr = [o for o, _ in objs if o.get("evento") == "arp_aprendido" and o.get("ip") == "10.0.4.95"]
    exp = [o for o, _ in objs if o.get("evento") == "arp_expirado" and o.get("ip") == "10.0.4.95"]
    confere(apr and apr[0].get("mac") == "02:00:00:00:0a:95" and apr[0].get("interface") == "eth1",
            f"arp_aprendido de 10.0.4.95: {apr[:1]}")
    confere(exp, "nenhum arp_expirado de 10.0.4.95")
    d = exp[0]["t"] - apr[0]["t"]
    confere(30.0 <= d <= 31.05, f"arp_expirado {d:.3f} s depois do arp_aprendido; esperado entre 30 e 31 s")


CAMPOS = {
    "inicio": ["t", "evento", "roteador"],
    "arp_aprendido": ["t", "evento", "ip", "mac", "interface"],
    "arp_expirado": ["t", "evento", "ip"],
    "arp_falhou": ["t", "evento", "ip", "interface"],
    "descarte": ["t", "evento", "motivo", "origem", "destino", "protocolo"],
}


@teste("Formato dos registros: só JSON na saída padrão, campos na ordem, t com três casas")
def _():
    for r in c.ROTEADORES:
        objs, brutas = c.registros(r, CONTEXTO["reinicio"])
        if brutas:
            raise Falhou(f"{r}: linha que não é JSON na saída padrão: {brutas[0][:100]!r}")
        for obj, linha in objs:
            ev = obj.get("evento")
            confere(ev in CAMPOS, f"{r}: evento desconhecido em {linha}")
            esperado = CAMPOS[ev] + (["regra"] if ev == "descarte" and obj.get("motivo") == "filtro" else [])
            confere(list(obj) == esperado, f"{r}: campos {list(obj)} em {linha}; esperados {esperado}")
            confere(re.search(r'^\{\s*"t"\s*:\s*\d+\.\d{3}\s*,', linha), f"{r}: t sem três casas decimais em {linha}")
            if ev == "descarte":
                confere(obj["motivo"] not in ("quadro", "cabecalho"), f"{r}: descarte {obj['motivo']} não gera registro")
                confere(isinstance(obj["protocolo"], int), f"{r}: protocolo não numérico em {linha}")
            if "mac" in obj:
                confere(re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", obj["mac"]), f"{r}: mac fora do formato em {linha}")


# ================================================================== configuração e filtragem

CONF_TESTE = """# Configuração dos testes: maior prefixo, rota padrão, rede conectada e filtragem

nome r1
interface eth0    10.0.1.1/24   02:00:00:00:01:00
interface  eth1 10.0.12.1/24 02:00:00:00:01:01

gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff
rota 0.0.0.0/0 via 10.0.12.2
rota 10.0.4.128/25 via 10.0.12.77
rota 10.0.1.0/24 via 10.0.12.2
filtro permitir icmp 10.0.1.10/32 * *
filtro negar icmp * 10.0.4.0/24 *
filtro negar * 10.0.1.0/24 10.0.4.0/25 *
filtro negar udp * * 7000
filtro negar icmp 10.0.4.11/32 * *
"""

R1_BASE = """nome r1
interface eth0 10.0.1.1/24 02:00:00:00:01:00
interface eth1 10.0.12.1/24 02:00:00:00:01:01
gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff
rota 10.0.23.0/24 via 10.0.12.2
rota 10.0.4.0/24 via 10.0.12.2
filtro negar udp 10.0.1.0/24 10.0.4.0/24 53
"""


def variante(trocar=None, acrescentar=None, remover=None):
    linhas = R1_BASE.splitlines()
    if remover:
        linhas = [l for l in linhas if not l.startswith(remover)]
    if trocar:
        linhas = [trocar[1] if l == trocar[0] else l for l in linhas]
    if acrescentar:
        linhas += acrescentar if isinstance(acrescentar, list) else [acrescentar]
    return "\n".join(linhas) + "\n"


INVALIDOS = [
    ("diretiva desconhecida", variante(acrescentar="rotas 10.0.9.0/24 via 10.0.12.2")),
    ("campo a mais", variante(trocar=("nome r1", "nome r1 extra"))),
    ("campo a menos", variante(acrescentar="rota 10.0.9.0/24 via")),
    ("sem nome", variante(remover="nome")),
    ("dois nome", variante(acrescentar="nome r9")),
    ("sem gerencia", variante(remover="gerencia")),
    ("duas gerencia", variante(acrescentar="gerencia eth2 192.168.200.1/24 02:00:00:00:01:fe")),
    ("sem interface", variante(remover="interface").replace("rota 10.0.23.0/24 via 10.0.12.2\n", "").replace("rota 10.0.4.0/24 via 10.0.12.2\n", "")),
    ("endereço inválido", variante(trocar=("interface eth0 10.0.1.1/24 02:00:00:00:01:00", "interface eth0 10.0.1.256/24 02:00:00:00:01:00"))),
    ("prefixo 33", variante(trocar=("interface eth0 10.0.1.1/24 02:00:00:00:01:00", "interface eth0 10.0.1.1/33 02:00:00:00:01:00"))),
    ("endereço físico maiúsculo", variante(trocar=("interface eth0 10.0.1.1/24 02:00:00:00:01:00", "interface eth0 10.0.1.1/24 02:00:00:00:01:0A"))),
    ("endereço físico com 5 pares", variante(trocar=("interface eth0 10.0.1.1/24 02:00:00:00:01:00", "interface eth0 10.0.1.1/24 02:00:00:00:01"))),
    ("ação inválida", variante(acrescentar="filtro bloquear udp * * 53")),
    ("protocolo tcp", variante(acrescentar="filtro negar tcp * * *")),
    ("porta com icmp", variante(acrescentar="filtro negar icmp * * 53")),
    ("porta com *", variante(acrescentar="filtro negar * * * 53")),
    ("porta 0", variante(acrescentar="filtro negar udp * * 0")),
    ("porta 65536", variante(acrescentar="filtro negar udp * * 65536")),
    ("interfaces com o mesmo nome", variante(trocar=("interface eth1 10.0.12.1/24 02:00:00:00:01:01", "interface eth0 10.0.12.1/24 02:00:00:00:01:01"))),
    ("mesmo endereço físico", variante(trocar=("interface eth1 10.0.12.1/24 02:00:00:00:01:01", "interface eth1 10.0.12.1/24 02:00:00:00:01:00"))),
    ("redes de dados sobrepostas", variante(trocar=("interface eth1 10.0.12.1/24 02:00:00:00:01:01", "interface eth1 10.0.0.1/16 02:00:00:00:01:01"))),
    ("gerência sobreposta a dados", variante(trocar=("gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff", "gerencia mgmt0 10.0.12.9/30 02:00:00:00:01:ff"))),
    ("endereço de rede na interface", variante(trocar=("interface eth0 10.0.1.1/24 02:00:00:00:01:00", "interface eth0 10.0.1.0/24 02:00:00:00:01:00"))),
    ("endereço de broadcast na interface", variante(trocar=("interface eth0 10.0.1.1/24 02:00:00:00:01:00", "interface eth0 10.0.1.255/24 02:00:00:00:01:00"))),
    ("rota com bits de host", variante(acrescentar="rota 10.0.9.5/24 via 10.0.12.2")),
    ("filtro com bits de host", variante(acrescentar="filtro negar udp 10.0.1.10/24 * 53")),
    ("rotas com o mesmo prefixo", variante(acrescentar="rota 10.0.4.0/24 via 10.0.12.3")),
    ("próximo salto fora das redes de dados", variante(acrescentar="rota 10.0.9.0/24 via 10.0.9.1")),
    ("próximo salto na rede de gerência", variante(acrescentar="rota 10.0.9.0/24 via 192.168.100.2")),
    ("próximo salto é o próprio roteador", variante(acrescentar="rota 10.0.9.0/24 via 10.0.12.1")),
    ("rota sem a palavra via", variante(acrescentar="rota 10.0.9.0/24 por 10.0.12.2")),
]


grupo("5. Arquivo de configuração")


@teste("Arquivos de configuração inválidos: motivo na saída de erro e código 1")
def _():
    import os
    pasta = os.path.join(c.ESTADO, "invalidos")
    os.makedirs(pasta, exist_ok=True)
    problemas = []
    for i, (nome, texto) in enumerate(INVALIDOS):
        caminho = os.path.join(pasta, f"{i:02d}.conf")
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(texto)
        r = c.docker("exec", "-w", "/opt/roteador", "r1", "timeout", "-s", "KILL", "4", "./roteador", caminho, tempo=30)
        if r.returncode != 1:
            situacao = "continuou rodando" if r.returncode in (124, 137) else f"terminou com código {r.returncode}"
            problemas.append(f"{nome}: {situacao}")
        elif not r.stderr.strip():
            problemas.append(f"{nome}: código 1, mas nada na saída de erro")
    confere(not problemas, f"{len(problemas)} de {len(INVALIDOS)} arquivos inválidos não foram recusados:\n            " +
            "\n            ".join(problemas))


grupo("6. Maior prefixo, rota padrão e filtragem (r1 com outro arquivo)", {"r1": CONF_TESTE})


@teste("Arquivo com comentário, linhas vazias e espaços repetidos é aceito")
def _():
    confere(CONTEXTO["problemas"].get("r1") is None, f"r1: {CONTEXTO['problemas'].get('r1')}")


@teste("Rota padrão: h1 alcança h2")
def _():
    saida = ping("h1", H2, "-c", "2", "-W", "2")
    confere(respostas_ping(saida, H2) == [61, 61], f"esperadas duas respostas com ttl=61\n            {resumo(saida)}")


@teste("Maior prefixo: 10.0.4.200 casa com 10.0.4.128/25 e o próximo salto não responde")
def _():
    saida = ping("h1", "10.0.4.200", "-c", "1", "-W", "5", tempo=30)
    confere(re.search(r"From 10\.0\.1\.1 .*Destination Host Unreachable", saida),
            f"esperado From 10.0.1.1 ... Destination Host Unreachable\n            {resumo(saida)}")


@teste("Rota padrão leva a r2, que não tem rota para 10.0.9.9")
def _():
    saida = ping("h1", "10.0.9.9", "-c", "1", "-W", "2")
    confere(re.search(r"From 10\.0\.12\.2 .*Destination Net Unreachable", saida),
            f"esperado From 10.0.12.2 ... Destination Net Unreachable\n            {resumo(saida)}")


@teste("Empate de prefixo: a rede conectada vence a rota estática")
def _():
    saida = ping("h2", H1, "-c", "2", "-W", "2")
    confere(respostas_ping(saida, H1) == [61, 61], f"esperadas duas respostas de {H1} com ttl=61\n            {resumo(saida)}")


@teste("Filtragem: a primeira regra que casa decide, sem mensagem ICMP")
def _():
    permitido = c.ipv4(H1, H2, 1, c.echo(0x81, 1), ident=0x8101)
    negado = c.ipv4("10.0.1.11", H2, 1, c.echo(0x82, 1), ident=0x8102)
    cap = c.capturar("h2", 1.2)
    _, capt = c.enviar("h1", [de_h1(permitido), de_h1(negado)], duracao=1.2, intervalo=0.05)
    ids = sorted(q.ip()["id"] for q in c.quadros(c.capturados(cap)) if q.eh_ip() and q.ip()["id"] in (0x8101, 0x8102))
    confere(ids == [0x8101], f"chegaram a h2 {[hex(i) for i in ids]}; esperado só o echo de 10.0.1.10, permitido pela regra 1")
    confere(not c.icmps(capt, (3, 13)) and not [m for _, m in c.icmps(capt) if m["tipo"] == 3],
            "h1 recebeu destino inalcançável; o pacote negado é descartado sem mensagem")


@teste("Filtragem sem estado: protocolo * nega h1 → h2 e não afeta h2 → h1")
def _():
    cap1 = c.capturar("h2", 1.0)
    c.enviar("h1", [de_h1(udp_ip(H1, H2, 9999, ident=0x8201))], duracao=0.3)
    ida = [q for q in c.quadros(c.capturados(cap1)) if q.eh_ip() and q.ip()["id"] == 0x8201]
    cap2 = c.capturar("h1", 1.0)
    c.enviar("h2", [de_h2(udp_ip(H2, H1, 9999, ident=0x8202))], duracao=0.3)
    volta = [q for q in c.quadros(c.capturados(cap2)) if q.eh_ip() and q.ip()["id"] == 0x8202]
    confere(not ida, "o UDP de h1 a h2 chegou, mas a regra 3 o nega")
    confere(len(volta) == 1, "o UDP de h2 a h1 não chegou; nenhuma regra o nega")


@teste("Filtragem por porta UDP de destino; fragmentos sem cabeçalho UDP não casam")
def _():
    estimulos = [
        udp_ip(H2, H1, 7000, ident=0x8301),
        udp_ip(H2, H1, 7001, ident=0x8302),
        c.ipv4(H2, H1, 17, b"\x00\x00\x1b\x58" + b"meio", ident=0x8303, flags_desloc=100),
    ]
    cap = c.capturar("h1", 1.2)
    c.enviar("h2", [de_h2(p) for p in estimulos], duracao=0.5, intervalo=0.05)
    ids = sorted(q.ip()["id"] for q in c.quadros(c.capturados(cap)) if q.eh_ip() and q.ip()["id"] in (0x8301, 0x8302, 0x8303))
    confere(ids == [0x8302, 0x8303], f"chegaram a h1 {[hex(i) for i in ids]}; esperados o da porta 7001 e o fragmento")


@teste("Filtragem não se aplica ao que é dirigido ao roteador nem ao que ele gera")
def _():
    falso_ip, falso_mac = "10.0.4.11", "02:00:00:00:0a:0b"
    resp = c.Sonda("h2", {"modo": "responder", "falsos": {falso_ip: falso_mac}, "atraso": 0, "duracao": 1.5})
    para_r1 = c.ipv4(falso_ip, "10.0.1.1", 1, c.echo(0x84, 1), ident=0x8401)
    para_h1 = c.ipv4(falso_ip, H1, 1, c.echo(0x85, 1), ident=0x8402)
    cap = c.capturar("h1", 1.2)
    c.enviar("h2", [de_h2(para_r1), de_h2(para_h1)], duracao=0.3, intervalo=0.05)
    r = resp.resultado()
    capt = c.quadros([(t, bytes.fromhex(h)) for t, h in r["capturados"]])
    respostas = [q for q in capt if q.eh_ip() and q.destino == falso_mac and q.icmp() and q.icmp()["tipo"] == 0]
    chegou_h1 = [q for q in c.quadros(c.capturados(cap)) if q.eh_ip() and q.ip()["id"] == 0x8402]
    confere(len(respostas) == 1 and respostas[0].ip()["origem"] == "10.0.1.1",
            "o echo de 10.0.4.11 a r1 ficou sem resposta; a regra 5 vale só para pacotes em trânsito")
    confere(not chegou_h1, "o echo de 10.0.4.11 a h1 chegou, mas a regra 5 o nega")


# ================================================================== execução

def selecionados(palavras):
    if not palavras:
        return TESTES
    p = [x.lower() for x in palavras]
    return [t for t in TESTES if any(x in t[1].lower() or x in GRUPOS[t[0]][0].lower() for x in p)]


def main():
    sys.stdout.reconfigure(line_buffering=True)
    print("Testes automáticos do roteador")
    if c.topologia_do_kernel():
        print("\nA topologia no ar é a do compose-kernel.yaml. Rode docker compose -f compose-kernel.yaml down "
              "e docker compose up -d --build antes dos testes.")
        return 2
    import os
    if os.path.exists(c.FALHA_ATIVA):
        print("\nHá um cenário de falha aplicado. Rode docker compose run --rm falha desfazer antes dos testes.")
        return 2

    painel = c.docker("ps", "-q", "--filter", "label=com.docker.compose.project=tp-roteador",
                      "--filter", "label=com.docker.compose.service=prometheus").stdout.strip()
    if painel:
        print("\nO Prometheus do perfil painel está no ar e consulta os roteadores a cada 5 s, o que muda as "
              "contagens. Rode docker compose stop prometheus antes dos testes.")
        return 2

    lista = selecionados(sys.argv[1:])
    if not lista:
        print("Nenhum teste com essas palavras.")
        return 2
    total = ok = 0
    conf_atual = None
    pendentes = []
    grupo_atual = None
    numero = {id(t): i + 1 for i, t in enumerate(TESTES)}

    def relatar(n, nome, erro):
        nonlocal ok, total
        total += 1
        if erro is None:
            ok += 1
            print(f"  OK      {n:2d}. {nome}")
        else:
            print(f"  FALHOU  {n:2d}. {nome}\n            {erro}")

    def fechar_grupo():
        for n, nome, concluir in pendentes:
            try:
                concluir()
                relatar(n, nome, None)
            except Falhou as e:
                relatar(n, nome, str(e))
            except Exception as e:  # noqa: BLE001
                relatar(n, nome, f"erro no teste: {e}")
        pendentes.clear()

    try:
        for t in lista:
            g, nome, f = t
            if g != grupo_atual:
                fechar_grupo()
                grupo_atual = g
                titulo, confs = GRUPOS[g]
                if confs != conf_atual or "reinicio" not in CONTEXTO:
                    c.gravar_configuracoes(confs)
                    CONTEXTO["reinicio"] = time.time()
                    CONTEXTO["problemas"] = c.reiniciar_roteadores()
                    conf_atual = confs
                print(f"\n{titulo}")
                for r, prob in CONTEXTO["problemas"].items():
                    if prob:
                        print(f"  aviso: {r}: {prob}")
            n = numero[id(t)]
            try:
                retorno = f()
                if callable(retorno):
                    pendentes.append((n, nome, retorno))
                    continue
                relatar(n, nome, None)
            except Falhou as e:
                relatar(n, nome, str(e))
            except Exception as e:  # noqa: BLE001
                relatar(n, nome, f"erro no teste: {e}")
                if os.environ.get("TESTES_DEPURAR"):
                    traceback.print_exc()
        fechar_grupo()
    finally:
        if conf_atual:
            print("\nRestaurando os arquivos de configuração da seção 3...")
            c.gravar_configuracoes({})
            c.reiniciar_roteadores()
        c.limpar_configuracoes()

    print(f"\nResultado: {ok} de {total} testes passaram.")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
