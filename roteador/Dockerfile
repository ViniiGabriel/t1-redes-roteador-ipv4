# Imagem de r1, r2 e r3. O grupo pode alterá-la para acrescentar a linguagem
# que escolher, com o compilador ou interpretador dela, mas não bibliotecas de
# terceiros (especificação, seção 2). Ela precisa continuar tendo sh, ip,
# tcpdump e pkill (procps).
# O código não entra na imagem: a pasta roteador/ é montada nos roteadores e
# copiada para /opt/roteador a cada início.
FROM debian:trixie-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 gcc g++ make libc6-dev \
      iproute2 tcpdump ethtool procps less \
 && rm -rf /var/lib/apt/lists/*
