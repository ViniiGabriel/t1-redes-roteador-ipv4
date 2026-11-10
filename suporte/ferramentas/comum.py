"""Funções comuns aos testes automáticos e ao serviço de falhas."""
import ipaddress
import re
import json
import os
import shutil
import struct
import subprocess
import time

ROTEADORES = ("r1", "r2", "r3")
MAQUINAS = ("h1", "h2", "gerente")
ESTADO = "/estado"
CONF_ESTADO = os.path.join(ESTADO, "configuracao")
FALHA_ATIVA = os.path.join(ESTADO, "falha-ativa")
SONDA = open(os.path.join(os.path.dirname(__file__), "sonda.py"), encoding="utf-8").read()

MAC = {
    "h1": "02:00:00:00:0a:01", "h2": "02:00:00:00:0a:02", "gerente": "02:00:00:00:0a:64",
    "r1.eth0": "02:00:00:00:01:00", "r1.eth1": "02:00:00:00:01:01", "r1.mgmt0": "02:00:00:00:01:ff",
    "r2.eth0": "02:00:00:00:02:00", "r2.eth1": "02:00:00:00:02:01", "r2.mgmt0": "02:00:00:00:02:ff",
    "r3.eth0": "02:00:00:00:03:00", "r3.eth1": "02:00:00:00:03:01", "r3.mgmt0": "02:00:00:00:03:ff",
}
GERENCIA = {"r1": "192.168.100.1", "r2": "192.168.100.2", "r3": "192.168.100.3"}
BROADCAST = "ff:ff:ff:ff:ff:ff"

METRICAS = [
    ("quadros_recebidos_eth0", "counter"), ("quadros_enviados_eth0", "counter"),
    ("quadros_recebidos_eth1", "counter"), ("quadros_enviados_eth1", "counter"),
    ("quadros_recebidos_mgmt0", "counter"), ("quadros_enviados_mgmt0", "counter"),
    ("pacotes_encaminhados", "counter"), ("icmp_gerados", "counter"), ("respostas_http", "counter"),
    ("arp_entradas", "gauge"), ("arp_pendentes", "gauge"),
    ("descartes_quadro", "counter"), ("descartes_cabecalho", "counter"), ("descartes_ttl", "counter"),
    ("descartes_sem_rota", "counter"), ("descartes_arp", "counter"), ("descartes_fila_arp", "counter"),
    ("descartes_filtro", "counter"), ("descartes_local", "counter"),
]


# ------------------------------------------------------------------ Docker

def docker(*args, entrada=None, tempo=60, verificar=False):
    r = subprocess.run(["docker", *args], input=entrada, capture_output=True, text=True, timeout=tempo)
    if verificar and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)}: {r.stderr.strip()}")
    return r


def executar(maquina, *comando, tempo=60, privilegiado=False):
    extra = ["--privileged"] if privilegiado else []
    return docker("exec", *extra, maquina, *comando, tempo=tempo)


def em_execucao(nome):
    r = docker("inspect", "-f", "{{.State.Running}}", nome)
    return r.returncode == 0 and r.stdout.strip() == "true"


def rotulo(nome, chave):
    r = docker("inspect", "-f", "{{index .Config.Labels \"" + chave + "\"}}", nome)
    return r.stdout.strip() if r.returncode == 0 else ""


def ambiente_env(nome, variavel):
    r = docker("inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", nome)
    for linha in r.stdout.splitlines():
        if linha.startswith(variavel + "="):
            return linha.split("=", 1)[1]
    return None


def topologia_do_kernel():
    return ambiente_env("r1", "MODO") == "kernel"


def estado_roteador(nome):
    r = executar(nome, "cat", "/run/roteador.estado")
    return r.stdout.strip() if r.returncode == 0 else "desconhecido"


# ------------------------------------------------------------------ configuração dos roteadores

def gravar_configuracoes(confs):
    """confs: {"r1": texto ou None}. None volta ao arquivo da seção 3."""
    os.makedirs(CONF_ESTADO, exist_ok=True)
    for r in ROTEADORES:
        caminho = os.path.join(CONF_ESTADO, f"{r}.conf")
        texto = confs.get(r)
        if texto is None:
            if os.path.exists(caminho):
                os.remove(caminho)
        else:
            with open(caminho, "w", encoding="utf-8") as f:
                f.write(texto)


def limpar_configuracoes():
    if os.path.isdir(CONF_ESTADO):
        shutil.rmtree(CONF_ESTADO)


def registros(nome, desde=0.0):
    """Linhas JSON da saída padrão do roteador com t >= desde, e as linhas que não são JSON."""
    r = docker("logs", "--since", str(int(desde) - 2) if desde else "0", nome, tempo=30)
    objetos, brutas = [], []
    for linha in r.stdout.splitlines():
        linha = linha.strip()
        if not linha:
            continue
        try:
            obj = json.loads(linha)
        except ValueError:
            brutas.append(linha)
            continue
        if isinstance(obj, dict) and isinstance(obj.get("t"), (int, float)) and obj["t"] < desde:
            continue
        objetos.append((obj, linha))
    return objetos, brutas


def reiniciar_roteadores(nomes=ROTEADORES, espera=180):
    """Reinicia os roteadores e espera o registro inicio de cada um. Devolve {nome: problema ou None}."""
    t0 = time.time()
    docker("restart", "-t", "5", *nomes, tempo=120)
    problemas = {n: "o registro inicio não apareceu" for n in nomes}
    fim = time.time() + espera
    while time.time() < fim and any(problemas.values()):
        for n in nomes:
            if problemas[n] is None:
                continue
            estado = estado_roteador(n)
            if estado.startswith(("terminou", "erro_build", "sem_executavel", "sem_codigo")):
                problemas[n] = f"o roteador não está em execução ({estado})"
                continue
            objs, _ = registros(n, t0)
            if any(o.get("evento") == "inicio" for o, _ in objs if isinstance(o, dict)):
                problemas[n] = None
        if all(p is None or "não está" in p for p in problemas.values()):
            break
        time.sleep(0.3)
    time.sleep(0.5)
    return problemas


# ------------------------------------------------------------------ sonda

class Sonda:
    """Executa sonda.py dentro de uma máquina, em primeiro plano ou em segundo plano."""

    def __init__(self, maquina, parametros):
        self.p = subprocess.Popen(
            ["docker", "exec", maquina, "python3", "-c", SONDA, json.dumps(parametros)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        linha = self.p.stderr.readline()
        if linha.strip() != "pronto" and parametros["modo"] != "udp":
            resto = self.p.stderr.read()
            raise RuntimeError(f"sonda em {maquina} não iniciou: {linha}{resto}")

    def resultado(self, tempo=120):
        saida, erro = self.p.communicate(timeout=tempo)
        if self.p.returncode != 0:
            raise RuntimeError(f"sonda falhou: {erro.strip()}")
        return json.loads(saida)


def sondar(maquina, parametros):
    return Sonda(maquina, parametros).resultado()


def enviar(maquina, quadros, duracao=1.0, intervalo=0.0, atraso=0.0):
    """Envia quadros (bytes) e devolve [(instante, bytes)] capturados na mesma máquina."""
    envios = [[atraso if i == 0 else intervalo, q.hex()] for i, q in enumerate(quadros)]
    r = sondar(maquina, {"modo": "quadros", "envios": envios, "duracao": duracao})
    return r["enviados"], [(t, bytes.fromhex(h)) for t, h in r["capturados"]]


def capturar(maquina, duracao):
    return Sonda(maquina, {"modo": "quadros", "envios": [], "duracao": duracao})


def capturados(sonda):
    return [(t, bytes.fromhex(h)) for t, h in sonda.resultado()["capturados"]]


def udp(maquina, destino, porta, dados, espera=2.0):
    r = sondar(maquina, {"modo": "udp", "destino": destino, "porta": porta, "dados": dados.hex(), "espera": espera})
    return r["porta_local"], (bytes.fromhex(r["resposta"]) if r["resposta"] is not None else None)


# ------------------------------------------------------------------ métricas

def metricas(roteador):
    """Dicionário de métricas por GET /metrics, ou None se não houver resposta 200."""
    r = executar("gerente", "metricas", GERENCIA[roteador], tempo=15)
    if r.returncode != 0 or not r.stdout.startswith("HTTP/1.1 200"):
        return None
    corpo = re.split(r"\r?\n\r?\n", r.stdout, 1)[-1]
    valores = {}
    for linha in corpo.split("\n"):
        if linha and not linha.startswith("#"):
            partes = linha.split()
            if len(partes) == 2:
                try:
                    valores[partes[0]] = int(partes[1])
                except ValueError:
                    pass
    return valores


# ------------------------------------------------------------------ montagem de quadros

def mac_bytes(texto):
    return bytes.fromhex(texto.replace(":", ""))


def mac_texto(b):
    return ":".join(f"{x:02x}" for x in b)


def ip_bytes(texto):
    return ipaddress.IPv4Address(texto).packed


def ip_texto(b):
    return str(ipaddress.IPv4Address(bytes(b)))


def soma16(dados):
    if len(dados) % 2:
        dados = bytes(dados) + b"\x00"
    s = sum(struct.unpack(f"!{len(dados) // 2}H", dados))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def checksum(dados):
    return (~soma16(dados)) & 0xFFFF


def eth(destino, origem, tipo, carga):
    return mac_bytes(destino) + mac_bytes(origem) + struct.pack("!H", tipo) + carga


def arp(operacao, sha, spa, tha, tpa, htype=1, ptype=0x0800, hlen=6, plen=4):
    return struct.pack("!HHBBH", htype, ptype, hlen, plen, operacao) + mac_bytes(sha) + ip_bytes(spa) + \
        mac_bytes(tha) + ip_bytes(tpa)


def ipv4(origem, destino, protocolo, dados, ttl=64, ident=0x1111, flags_desloc=0, opcoes=b"", tos=0,
         total=None, soma=None, versao=4, ihl=None):
    if ihl is None:
        ihl = 5 + len(opcoes) // 4
    tot = total if total is not None else 4 * (5 + len(opcoes) // 4) + len(dados)
    cab = bytearray(struct.pack("!BBHHHBBH4s4s", (versao << 4) | ihl, tos, tot, ident, flags_desloc, ttl,
                                protocolo, 0, ip_bytes(origem), ip_bytes(destino)) + opcoes)
    cab[10:12] = struct.pack("!H", checksum(cab) if soma is None else soma)
    return bytes(cab) + dados


def icmp(tipo, codigo, resto, soma=None):
    m = bytearray(struct.pack("!BBH", tipo, codigo, 0) + resto)
    m[2:4] = struct.pack("!H", checksum(m) if soma is None else soma)
    return bytes(m)


def echo(ident, seq, dados=b"", tipo=8, soma=None):
    return icmp(tipo, 0, struct.pack("!HH", ident, seq) + dados, soma)


def udp_seg(origem, destino, porta_origem, porta_destino, dados, soma="calcular", tamanho=None):
    tam = tamanho if tamanho is not None else 8 + len(dados)
    seg = bytearray(struct.pack("!HHHH", porta_origem, porta_destino, tam, 0) + dados)
    if soma == "calcular":
        pseudo = ip_bytes(origem) + ip_bytes(destino) + struct.pack("!BBH", 0, 17, len(seg))
        seg[6:8] = struct.pack("!H", checksum(pseudo + seg) or 0xFFFF)
    elif soma is not None:
        seg[6:8] = struct.pack("!H", soma)
    return bytes(seg)


# ------------------------------------------------------------------ leitura de quadros

class Quadro:
    def __init__(self, t, b):
        self.t = t
        self.b = b
        self.destino = mac_texto(b[0:6])
        self.origem = mac_texto(b[6:12])
        self.tipo = struct.unpack("!H", b[12:14])[0]
        self.carga = b[14:]

    def eh_arp(self):
        return self.tipo == 0x0806 and len(self.carga) >= 28

    def arp(self):
        c = self.carga
        return {"op": struct.unpack("!H", c[6:8])[0], "sha": mac_texto(c[8:14]), "spa": ip_texto(c[14:18]),
                "tha": mac_texto(c[18:24]), "tpa": ip_texto(c[24:28]),
                "cab": struct.unpack("!HHBB", c[0:6])}

    def eh_ip(self):
        return self.tipo == 0x0800 and len(self.carga) >= 20

    def ip(self):
        c = self.carga
        ihl = (c[0] & 0x0F) * 4
        total = struct.unpack("!H", c[2:4])[0]
        p = c[:total]
        return {"versao": c[0] >> 4, "ihl": ihl, "tos": c[1], "total": total,
                "id": struct.unpack("!H", c[4:6])[0], "frag": struct.unpack("!H", c[6:8])[0],
                "ttl": c[8], "proto": c[9], "soma_ok": soma16(c[:ihl]) == 0xFFFF,
                "origem": ip_texto(c[12:16]), "destino": ip_texto(c[16:20]),
                "cab": bytes(c[:ihl]), "dados": bytes(p[ihl:]), "pacote": bytes(p)}

    def icmp(self):
        i = self.ip()
        d = i["dados"]
        if i["proto"] != 1 or len(d) < 8:
            return None
        return {"tipo": d[0], "codigo": d[1], "soma_ok": soma16(d) == 0xFFFF,
                "resto": d[4:8], "corpo": d[8:], "ip": i}


def quadros(lista):
    return [Quadro(t, b) for t, b in lista]


def icmps(lista, tipo=None, origem=None):
    saida = []
    for q in quadros(lista):
        if q.eh_ip():
            m = q.icmp()
            if m and (tipo is None or (m["tipo"], m["codigo"]) == tipo) and \
                    (origem is None or m["ip"]["origem"] == origem):
                saida.append((q, m))
    return saida
