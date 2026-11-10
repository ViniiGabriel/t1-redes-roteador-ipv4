"""Cenários de falha do vídeo individual: docker compose run --rm falha CENARIO

Cada cenário tem um nome, um tipo, a descrição do que muda e as ações que o serviço
falha aplica. A descrição é pública: o aviso do Moodle mostra a de cada estudante.
Ações, uma por lista:
  L maquina                 desliga a eth0 da máquina
  I maquina endereco        troca o endereço da eth0 da máquina, mantendo o prefixo /24 e a rota padrão
  R roteador linha          remove a linha do arquivo de configuração do roteador
  A roteador linha          acrescenta a linha ao fim do arquivo de configuração
  S roteador antiga nova    troca a linha antiga pela nova, no mesmo lugar do arquivo
  P maquina interface perda aplica perda de quadros, em porcentagem, na saída da interface
  T maquina ttl             muda o TTL inicial da máquina
  G maquina endereco        troca a rota padrão da máquina
  N maquina endereco mac    grava uma entrada ARP permanente na máquina
"""


def _cenario(nome, tipo, descricao, *acoes):
    return {"id": nome, "tipo": tipo, "descricao": descricao, "acoes": [list(a) for a in acoes]}


CENARIOS = [
    # Máquina ausente
    _cenario("ausente-h2", "maquina_ausente", "A interface eth0 de h2 está desligada.", ("L", "h2")),
    _cenario("endereco-h2", "maquina_ausente", "O endereço de h2 passou de 10.0.4.10 para 10.0.4.20.",
             ("I", "h2", "10.0.4.20")),

    # Próximo salto inexistente
    _cenario("salto-r1-10.0.23.0", "proximo_salto",
             "A rota de r1 para 10.0.23.0/24 aponta para 10.0.12.77, endereço que ninguém usa, em vez de 10.0.12.2.",
             ("R", "r1", "rota 10.0.23.0/24 via 10.0.12.2"), ("A", "r1", "rota 10.0.23.0/24 via 10.0.12.77")),
    _cenario("salto-r1-10.0.4.0", "proximo_salto",
             "A rota de r1 para 10.0.4.0/24 aponta para 10.0.12.77, endereço que ninguém usa, em vez de 10.0.12.2.",
             ("R", "r1", "rota 10.0.4.0/24 via 10.0.12.2"), ("A", "r1", "rota 10.0.4.0/24 via 10.0.12.77")),
    _cenario("salto-r2-10.0.1.0", "proximo_salto",
             "A rota de r2 para 10.0.1.0/24 aponta para 10.0.12.77, endereço que ninguém usa, em vez de 10.0.12.1.",
             ("R", "r2", "rota 10.0.1.0/24 via 10.0.12.1"), ("A", "r2", "rota 10.0.1.0/24 via 10.0.12.77")),
    _cenario("salto-r2-10.0.4.0", "proximo_salto",
             "A rota de r2 para 10.0.4.0/24 aponta para 10.0.23.77, endereço que ninguém usa, em vez de 10.0.23.3.",
             ("R", "r2", "rota 10.0.4.0/24 via 10.0.23.3"), ("A", "r2", "rota 10.0.4.0/24 via 10.0.23.77")),
    _cenario("salto-r3-10.0.1.0", "proximo_salto",
             "A rota de r3 para 10.0.1.0/24 aponta para 10.0.23.77, endereço que ninguém usa, em vez de 10.0.23.2.",
             ("R", "r3", "rota 10.0.1.0/24 via 10.0.23.2"), ("A", "r3", "rota 10.0.1.0/24 via 10.0.23.77")),

    # Rota ausente
    _cenario("semrota-r1-10.0.23.0", "rota_ausente", "A linha \"rota 10.0.23.0/24 via 10.0.12.2\" saiu de r1.",
             ("R", "r1", "rota 10.0.23.0/24 via 10.0.12.2")),
    _cenario("semrota-r1-10.0.4.0", "rota_ausente", "A linha \"rota 10.0.4.0/24 via 10.0.12.2\" saiu de r1.",
             ("R", "r1", "rota 10.0.4.0/24 via 10.0.12.2")),
    _cenario("semrota-r2-10.0.1.0", "rota_ausente", "A linha \"rota 10.0.1.0/24 via 10.0.12.1\" saiu de r2.",
             ("R", "r2", "rota 10.0.1.0/24 via 10.0.12.1")),
    _cenario("semrota-r2-10.0.4.0", "rota_ausente", "A linha \"rota 10.0.4.0/24 via 10.0.23.3\" saiu de r2.",
             ("R", "r2", "rota 10.0.4.0/24 via 10.0.23.3")),
    _cenario("semrota-r3-10.0.1.0", "rota_ausente", "A linha \"rota 10.0.1.0/24 via 10.0.23.2\" saiu de r3.",
             ("R", "r3", "rota 10.0.1.0/24 via 10.0.23.2")),

    # Rota mais específica
    _cenario("especifica-r1-h2", "rota_especifica",
             "r1 ganhou a rota \"rota 10.0.4.10/32 via 10.0.12.77\", com próximo salto que ninguém usa, além da rota "
             "para 10.0.4.0/24.", ("A", "r1", "rota 10.0.4.10/32 via 10.0.12.77")),
    _cenario("especifica-r2-h2", "rota_especifica",
             "r2 ganhou a rota \"rota 10.0.4.10/32 via 10.0.12.1\", que aponta de volta para r1, além da rota para "
             "10.0.4.0/24.", ("A", "r2", "rota 10.0.4.10/32 via 10.0.12.1")),
    _cenario("especifica-r2-h1", "rota_especifica",
             "r2 ganhou a rota \"rota 10.0.1.10/32 via 10.0.23.3\", que aponta de volta para r3, além da rota para "
             "10.0.1.0/24.", ("A", "r2", "rota 10.0.1.10/32 via 10.0.23.3")),

    # Máscara errada
    _cenario("mascara-r1-eth0", "mascara",
             "A interface eth0 de r1 passou de 10.0.1.1/24 para 10.0.1.1/29.",
             ("S", "r1", "interface eth0 10.0.1.1/24 02:00:00:00:01:00", "interface eth0 10.0.1.1/29 02:00:00:00:01:00")),
    _cenario("mascara-r3-eth1", "mascara",
             "A interface eth1 de r3 passou de 10.0.4.1/24 para 10.0.4.1/29.",
             ("S", "r3", "interface eth1 10.0.4.1/24 02:00:00:00:03:01", "interface eth1 10.0.4.1/29 02:00:00:00:03:01")),

    # Filtro acrescentado
    _cenario("filtro-r1-1", "filtro", "r1 ganhou, depois da regra que já tinha, a regra \"filtro negar icmp * 10.0.4.0/24 *\".",
             ("A", "r1", "filtro negar icmp * 10.0.4.0/24 *")),
    _cenario("filtro-r1-2", "filtro", "r1 ganhou, depois da regra que já tinha, a regra \"filtro negar icmp 10.0.4.0/24 * *\".",
             ("A", "r1", "filtro negar icmp 10.0.4.0/24 * *")),
    _cenario("filtro-r1-3", "filtro", "r1 ganhou, depois da regra que já tinha, a regra \"filtro negar udp * 10.0.4.0/24 *\".",
             ("A", "r1", "filtro negar udp * 10.0.4.0/24 *")),
    _cenario("filtro-r1-4", "filtro", "r1 ganhou, depois da regra que já tinha, a regra \"filtro negar * * 10.0.23.0/24 *\".",
             ("A", "r1", "filtro negar * * 10.0.23.0/24 *")),
    _cenario("filtro-r2-1", "filtro", "r2 ganhou a regra \"filtro negar icmp * 10.0.4.0/24 *\".",
             ("A", "r2", "filtro negar icmp * 10.0.4.0/24 *")),
    _cenario("filtro-r2-2", "filtro", "r2 ganhou a regra \"filtro negar icmp 10.0.4.0/24 10.0.1.0/24 *\".",
             ("A", "r2", "filtro negar icmp 10.0.4.0/24 10.0.1.0/24 *")),
    _cenario("filtro-r2-3", "filtro", "r2 ganhou a regra \"filtro negar udp 10.0.1.0/24 * *\".",
             ("A", "r2", "filtro negar udp 10.0.1.0/24 * *")),
    _cenario("filtro-r2-4", "filtro", "r2 ganhou a regra \"filtro negar * 10.0.1.10/32 * *\".",
             ("A", "r2", "filtro negar * 10.0.1.10/32 * *")),
    _cenario("filtro-r3-1", "filtro", "r3 ganhou a regra \"filtro negar icmp * 10.0.4.10/32 *\".",
             ("A", "r3", "filtro negar icmp * 10.0.4.10/32 *")),
    _cenario("filtro-r3-2", "filtro", "r3 ganhou a regra \"filtro negar udp * * *\".",
             ("A", "r3", "filtro negar udp * * *")),
    _cenario("filtro-r3-3", "filtro", "r3 ganhou a regra \"filtro negar icmp 10.0.4.10/32 * *\".",
             ("A", "r3", "filtro negar icmp 10.0.4.10/32 * *")),

    # Perda num enlace
    _cenario("perda-h1-eth0", "perda", "Perda de 50% dos quadros na saída da eth0 de h1.", ("P", "h1", "eth0", "50")),
    _cenario("perda-r2-eth1", "perda", "Perda de 50% dos quadros na saída da eth1 de r2.", ("P", "r2", "eth1", "50")),

    # Enlace desligado
    _cenario("enlace-r1-r2", "enlace_desligado",
             "O enlace entre r1 e r2 perde todos os quadros, nos dois sentidos.",
             ("P", "r1", "eth1", "100"), ("P", "r2", "eth0", "100")),
    _cenario("enlace-r2-r3", "enlace_desligado",
             "O enlace entre r2 e r3 perde todos os quadros, nos dois sentidos.",
             ("P", "r2", "eth1", "100"), ("P", "r3", "eth0", "100")),

    # TTL inicial baixo
    _cenario("ttl-h1-2", "ttl", "O TTL inicial de h1 é 2, e não 64.", ("T", "h1", "2")),
    _cenario("ttl-h2-2", "ttl", "O TTL inicial de h2 é 2, e não 64.", ("T", "h2", "2")),

    # Rota padrão errada
    _cenario("padrao-h1", "rota_padrao", "A rota padrão de h1 aponta para 10.0.1.77, que ninguém usa, em vez de 10.0.1.1.",
             ("G", "h1", "10.0.1.77")),
    _cenario("padrao-h2", "rota_padrao", "A rota padrão de h2 aponta para 10.0.4.77, que ninguém usa, em vez de 10.0.4.1.",
             ("G", "h2", "10.0.4.77")),

    # Endereço físico errado
    _cenario("mac-h1-99", "mac_errado",
             "h1 tem uma entrada ARP permanente que associa 10.0.1.1 a 02:00:00:00:01:99, endereço físico que nenhuma "
             "interface usa.", ("N", "h1", "10.0.1.1", "02:00:00:00:01:99")),
    _cenario("mac-h1-01", "mac_errado",
             "h1 tem uma entrada ARP permanente que associa 10.0.1.1 a 02:00:00:00:01:01, o endereço físico da eth1 de r1.",
             ("N", "h1", "10.0.1.1", "02:00:00:00:01:01")),
    _cenario("mac-h2-99", "mac_errado",
             "h2 tem uma entrada ARP permanente que associa 10.0.4.1 a 02:00:00:00:03:99, endereço físico que nenhuma "
             "interface usa.", ("N", "h2", "10.0.4.1", "02:00:00:00:03:99")),
    _cenario("mac-h2-00", "mac_errado",
             "h2 tem uma entrada ARP permanente que associa 10.0.4.1 a 02:00:00:00:03:00, o endereço físico da eth0 de r3.",
             ("N", "h2", "10.0.4.1", "02:00:00:00:03:00")),

    # Endereço de gerência errado
    _cenario("gerencia-r1", "gerencia",
             "O endereço de gerência de r1, no arquivo de configuração, passou de 192.168.100.1 para 192.168.100.11.",
             ("S", "r1", "gerencia mgmt0 192.168.100.1/24 02:00:00:00:01:ff", "gerencia mgmt0 192.168.100.11/24 02:00:00:00:01:ff")),
    _cenario("gerencia-r2", "gerencia",
             "O endereço de gerência de r2, no arquivo de configuração, passou de 192.168.100.2 para 192.168.100.12.",
             ("S", "r2", "gerencia mgmt0 192.168.100.2/24 02:00:00:00:02:ff", "gerencia mgmt0 192.168.100.12/24 02:00:00:00:02:ff")),
]

POR_NOME = {c["id"]: c for c in CENARIOS}

# Cenários de ensaio, publicados com o ambiente; o sorteio dos cenários individuais os deixa de fora.
# "exemplo" é o nome do primeiro antes de 17/10/2026 e continua aceito.
EXEMPLOS = {"exemplo1": "semrota-r2-10.0.1.0", "exemplo2": "filtro-r3-1", "exemplo3": "salto-r2-10.0.4.0",
            "exemplo": "semrota-r2-10.0.1.0"}
