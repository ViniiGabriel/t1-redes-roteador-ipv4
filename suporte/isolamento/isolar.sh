#!/bin/sh
# Mantém os enlaces da topologia livres de quadros e filtros do computador hospedeiro.
#
# O Docker cria, no hospedeiro, a ponte de cada rede e uma ponta de cada par veth.
# Essas interfaces recebem endereço IPv6 de enlace local, e o hospedeiro passa a
# emitir por elas solicitações de roteador, relatórios MLD, mDNS e outras mensagens
# multicast, que chegariam aos roteadores e mudariam as contagens. Este laço
# desliga o IPv6 nas pontes tpr-* e em toda interface ligada a elas, inclusive nas
# pontas veth recriadas quando um contêiner reinicia.
#
# Com o br_netfilter ativo, como na máquina virtual do Docker Desktop, a ponte passa
# cada quadro pelo netfilter do hospedeiro: corta o preenchimento dos quadros curtos,
# descarta cabeçalhos IPv4 malformados e remonta ou descarta fragmentos e TCP fora de
# conexão antes que cheguem ao roteador. Enquanto a topologia estiver no ar, as pontes
# não chamam o netfilter; ao terminar, as chaves voltam aos valores anteriores.
#
# O Docker liga o modo hairpin nas portas das pontes quando o userland-proxy está
# desligado, como no Docker Desktop. Com ele, a ponte devolve a cada contêiner os
# quadros de broadcast que ele próprio enviou, e o roteador os recebe como quadros de
# entrada: conta as próprias requisições ARP e responde aos anúncios ARP que o Docker
# faz do endereço de cada interface ao iniciar o contêiner. O laço desliga o hairpin
# em toda porta das pontes tpr-*, para que cada enlace ligue só as duas máquinas.
BR=/proc/sys/net/bridge
CHAVES="bridge-nf-call-iptables bridge-nf-call-ip6tables bridge-nf-call-arptables"
ORIGINAIS=""
for k in $CHAVES; do
  [ -w "$BR/$k" ] && ORIGINAIS="$ORIGINAIS $k=$(cat "$BR/$k")"
done

restaurar() {
  for par in $ORIGINAIS; do
    echo "${par#*=}" > "$BR/${par%%=*}" 2>/dev/null
  done
  exit 0
}
trap restaurar TERM INT

while :; do
  for k in $CHAVES; do
    [ -w "$BR/$k" ] && [ "$(cat "$BR/$k" 2>/dev/null)" != 0 ] && echo 0 > "$BR/$k" 2>/dev/null
  done
  for ponte in /sys/class/net/tpr-*; do
    [ -d "$ponte" ] || continue
    nome=${ponte##*/}
    for i in "$nome" $(ls "$ponte/brif" 2>/dev/null); do
      arq=/proc/sys/net/ipv6/conf/$i/disable_ipv6
      [ -w "$arq" ] && [ "$(cat "$arq" 2>/dev/null)" != 1 ] && echo 1 > "$arq" 2>/dev/null
    done
    for porta in "$ponte"/brif/*; do
      arq=$porta/hairpin_mode
      [ -w "$arq" ] && [ "$(cat "$arq" 2>/dev/null)" != 0 ] && echo 0 > "$arq" 2>/dev/null
    done
  done
  sleep 0.1
done
