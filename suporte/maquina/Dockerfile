# Imagem de h1, h2 e g, e dos roteadores do compose-kernel.yaml.
FROM debian:trixie-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iproute2 iputils-ping traceroute dnsutils iperf3 tcpdump ethtool \
      python3 procps less netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

COPY iniciar.sh /usr/local/sbin/iniciar-maquina
COPY metricas injetar /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/sbin/iniciar-maquina /usr/local/bin/metricas /usr/local/bin/injetar \
 && chmod +x /usr/local/sbin/iniciar-maquina /usr/local/bin/metricas /usr/local/bin/injetar

CMD ["iniciar-maquina"]
