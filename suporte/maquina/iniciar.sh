#!/bin/sh
# Prepara a rede de h1, h2 e g, ou de um roteador do compose-kernel.yaml, e fica no ar.
#   GATEWAY  rota padrão da máquina (h1 e h2); vazio em g
#   ROTAS    rotas estáticas do roteador do Linux, separadas por ";"
set -u

# Sem descarga de checksum e de segmentação: todo quadro sai completo e com no máximo 1514 bytes.
for i in $(ls /sys/class/net); do
  [ "$i" = lo ] && continue
  ethtool -K "$i" rx off tx off sg off tso off gso off gro off >/dev/null 2>&1 || true
done

# O Docker instala uma rota padrão pelo gateway da própria rede, que não existe na topologia.
ip route del default >/dev/null 2>&1 || true
if [ -n "${GATEWAY:-}" ]; then
  ip route add default via "$GATEWAY" dev eth0
fi

if [ -n "${ROTAS:-}" ]; then
  echo "$ROTAS" | tr ';' '\n' | while read -r rota; do
    [ -n "$rota" ] && ip route add $rota
  done
fi

exec sleep infinity
