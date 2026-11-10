#!/bin/sh
# Inicia o programa do grupo num roteador (especificação, seção 2).
#   NOME  nome do roteador e do arquivo de configuração: r1, r2 ou r3
# Mensagens deste script vão para a saída de erro; a saída padrão é só do programa.
set -u
NOME=${NOME:?defina NOME}
ESTADO=/run/roteador.estado

aviso() { echo "[ambiente] $*" >&2; }

# Fica no ar sem o programa, para que tcpdump e docker exec continuem funcionando.
aguardar() {
  echo "$1" > "$ESTADO"
  trap 'exit 0' TERM INT
  while :; do sleep 3600 & wait $!; done
}

# As interfaces do roteador não têm endereço no sistema: quem responde é o programa.
# Só as três da topologia: o kernel do Docker Desktop cria também interfaces de túnel
# (gre0, erspan0, tunl0...) em cada contêiner, que não fazem parte da rede.
for i in eth0 eth1 mgmt0; do
  [ -e "/sys/class/net/$i" ] || continue
  ip -4 addr flush dev "$i"
  ip link set "$i" up
  ethtool -K "$i" rx off tx off sg off tso off gso off gro off >/dev/null 2>&1 || true
done

# Arquivo de configuração: o da seção 3, ou o que os testes ou o serviço de falhas puseram no lugar.
mkdir -p /opt/configuracao
if [ -f "/estado/configuracao/$NOME.conf" ]; then
  cp "/estado/configuracao/$NOME.conf" "/opt/configuracao/$NOME.conf"
else
  cp "/configuracao/$NOME.conf" "/opt/configuracao/$NOME.conf"
fi
CONF="/opt/configuracao/$NOME.conf"

# Cópia própria do código: r1, r2 e r3 compilam cada um a sua.
rm -rf /opt/roteador
cp -r /fonte/roteador /opt/roteador
cd /opt/roteador || aguardar "sem_codigo"

[ -f build.sh ] && sed -i 's/\r$//' build.sh
if [ -f roteador ] && [ "$(head -c 2 roteador)" = "#!" ]; then
  sed -i 's/\r$//' roteador
fi

if [ -f build.sh ]; then
  aviso "$NOME: executando build.sh"
  if ! sh build.sh >&2; then
    aviso "$NOME: build.sh terminou com erro; o roteador não foi iniciado"
    aguardar "erro_build"
  fi
fi

if [ ! -f roteador ]; then
  aviso "$NOME: não há o executável roteador em roteador/; a máquina fica no ar sem roteador"
  aguardar "sem_executavel"
fi

chmod +x roteador
aviso "$NOME: iniciando ./roteador $CONF"
./roteador "$CONF" &
pid=$!
echo "executando $pid" > "$ESTADO"
trap 'kill -TERM "$pid" 2>/dev/null; wait "$pid"; exit 0' TERM INT
wait "$pid"
codigo=$?
aviso "$NOME: o roteador terminou com código $codigo"
aguardar "terminou $codigo"
