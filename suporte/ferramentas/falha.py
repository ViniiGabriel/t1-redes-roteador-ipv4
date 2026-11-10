"""Serviço de falhas: docker compose run --rm falha CENARIO | exemplo1 | exemplo2 | exemplo3 | desfazer

Aplica à rede no ar o cenário de falha de nome dado, descrito em cenarios.py, ou desfaz o
cenário. O cenário muda só a rede em volta do roteador: máquinas, enlaces e arquivos de
configuração. Os arquivos alterados são cópias no volume do ambiente; a pasta
configuracao/ do repositório não muda.
"""
import os
import sys

import comum as c
from cenarios import EXEMPLOS, POR_NOME

# Arquivos da seção 3 da especificação: a base de todo cenário.
SECAO_3 = {
    "r1": """nome r1
interface eth0 10.0.1.1/24 02:00:00:00:01:00
interface eth1 10.0.12.1/24 02:00:00:00:01:01
gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff
rota 10.0.23.0/24 via 10.0.12.2
rota 10.0.4.0/24 via 10.0.12.2
filtro negar udp 10.0.1.0/24 10.0.4.0/24 53
""",
    "r2": """nome r2
interface eth0 10.0.12.2/24 02:00:00:00:02:00
interface eth1 10.0.23.2/24 02:00:00:00:02:01
gerencia mgmt0 192.168.100.2/24 02:00:00:00:02:ff
rota 10.0.1.0/24 via 10.0.12.1
rota 10.0.4.0/24 via 10.0.23.3
""",
    "r3": """nome r3
interface eth0 10.0.23.3/24 02:00:00:00:03:00
interface eth1 10.0.4.1/24 02:00:00:00:03:01
gerencia mgmt0 192.168.100.3/24 02:00:00:00:03:ff
rota 10.0.1.0/24 via 10.0.23.2
rota 10.0.12.0/24 via 10.0.23.2
""",
}

GATEWAY = {"h1": "10.0.1.1", "h2": "10.0.4.1"}
ENDERECO = {"h1": "10.0.1.10/24", "h2": "10.0.4.10/24"}
IMAGEM_AUXILIAR = "tp-roteador-ferramentas:1"


def falhar(mensagem):
    print(mensagem)
    sys.exit(1)


def no_roteador(roteador, *comando):
    """Executa um comando de rede no espaço de rede do roteador, sem depender da imagem do grupo."""
    return c.docker("run", "--rm", "--network", f"container:{roteador}", "--cap-add", "NET_ADMIN",
                    "--entrypoint", comando[0], IMAGEM_AUXILIAR, *comando[1:], tempo=60)


def ttl_inicial(maquina, ttl):
    """O /proc/sys das máquinas é só de leitura; um contêiner privilegiado no mesmo espaço de rede o altera."""
    return c.docker("run", "--rm", "--privileged", "--network", f"container:{maquina}", "--entrypoint", "sysctl",
                    IMAGEM_AUXILIAR, "-q", "-w", f"net.ipv4.ip_default_ttl={ttl}", tempo=60)


def em(maquina, *comando, privilegiado=False):
    if maquina in c.ROTEADORES:
        return no_roteador(maquina, *comando)
    return c.executar(maquina, *comando, privilegiado=privilegiado)


def verificar_topologia():
    fora = [n for n in c.ROTEADORES + c.MAQUINAS if not c.em_execucao(n)]
    if fora:
        falhar(f"A topologia não está completa no ar: {', '.join(fora)}. Rode docker compose up -d --build.")
    if c.topologia_do_kernel():
        falhar("A topologia no ar é a do compose-kernel.yaml. Rode docker compose -f compose-kernel.yaml down "
               "e docker compose up -d --build.")


def trocar_endereco(maquina, endereco):
    """Deixa na eth0 só o endereço dado, com o prefixo /24, e refaz a rota padrão, que cai junto com o endereço antigo."""
    c.executar(maquina, "ip", "-4", "addr", "flush", "dev", "eth0", privilegiado=True)
    c.executar(maquina, "ip", "addr", "add", endereco, "dev", "eth0", privilegiado=True)
    c.executar(maquina, "ip", "route", "replace", "default", "via", GATEWAY[maquina], "dev", "eth0")


def restaurar_maquinas():
    for m in c.MAQUINAS:
        c.executar(m, "ip", "link", "set", "eth0", "up")
        if m in ENDERECO:
            atual = c.executar(m, "ip", "-4", "-o", "addr", "show", "dev", "eth0").stdout.split()
            if ENDERECO[m] not in atual or len([x for x in atual if x == "inet"]) != 1:
                trocar_endereco(m, ENDERECO[m])
        c.executar(m, "tc", "qdisc", "del", "dev", "eth0", "root")
        if m in GATEWAY:
            ttl_inicial(m, 64)
        c.executar(m, "ip", "neigh", "flush", "dev", "eth0", "nud", "all")
        if m in GATEWAY:
            c.executar(m, "ip", "route", "replace", "default", "via", GATEWAY[m], "dev", "eth0")
    for r in c.ROTEADORES:
        no_roteador(r, "sh", "-c", "for i in eth0 eth1 mgmt0; do tc qdisc del dev $i root 2>/dev/null; done")


def desfazer():
    verificar_topologia()
    restaurar_maquinas()
    c.limpar_configuracoes()
    if os.path.exists(c.FALHA_ATIVA):
        os.remove(c.FALHA_ATIVA)
    problemas = c.reiniciar_roteadores()
    for r, p in problemas.items():
        if p:
            print(f"aviso: {r}: {p}")
    print("Rede devolvida ao estado das seções 1 e 3 da especificação.")


def aplicar(acoes):
    verificar_topologia()
    restaurar_maquinas()
    confs = {r: SECAO_3[r].splitlines() for r in c.ROTEADORES}
    for a in acoes:
        if a[0] == "R":
            if a[2] not in confs[a[1]]:
                falhar("Cenário inválido para esta versão do ambiente.")
            confs[a[1]].remove(a[2])
        elif a[0] == "A":
            confs[a[1]].append(a[2])
        elif a[0] == "S":
            if a[2] not in confs[a[1]]:
                falhar("Cenário inválido para esta versão do ambiente.")
            confs[a[1]][confs[a[1]].index(a[2])] = a[3]
    c.gravar_configuracoes({r: "\n".join(l) + "\n" for r, l in confs.items()})
    with open(c.FALHA_ATIVA, "w", encoding="utf-8") as f:
        f.write("1\n")
    problemas = c.reiniciar_roteadores()
    for r, p in problemas.items():
        if p:
            print(f"aviso: {r}: {p}")

    for a in acoes:
        tipo = a[0]
        if tipo == "L":
            em(a[1], "ip", "link", "set", "eth0", "down")
        elif tipo == "P":
            em(a[1], "tc", "qdisc", "replace", "dev", a[2], "root", "netem", "loss", f"{a[3]}%")
        elif tipo == "T":
            ttl_inicial(a[1], a[2])
        elif tipo == "G":
            em(a[1], "ip", "route", "replace", "default", "via", a[2], "dev", "eth0")
        elif tipo == "I":
            trocar_endereco(a[1], a[2] + "/24")
        elif tipo == "N":
            em(a[1], "ip", "neigh", "replace", a[2], "lladdr", a[3], "dev", "eth0", "nud", "permanent")
    print("Cenário aplicado.")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    if len(sys.argv) != 2:
        falhar("uso: docker compose run --rm falha CENARIO, exemplo1, exemplo2, exemplo3 ou desfazer")
    arg = sys.argv[1].strip()
    if arg == "desfazer":
        desfazer()
        return
    cenario = POR_NOME.get(EXEMPLOS.get(arg, arg))
    if cenario is None:
        falhar(f"Não há cenário com o nome {arg}. Confira o nome no aviso do Moodle.")
    print(cenario["descricao"])
    aplicar(cenario["acoes"])


if __name__ == "__main__":
    main()
