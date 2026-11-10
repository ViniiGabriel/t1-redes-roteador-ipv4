# Ambiente do trabalho prático: roteador IPv4 em software

Esta pasta é o repositório do grupo. Ela monta, com o Docker Compose, a rede da especificação do roteador publicada no Moodle: h1, r1, r2, r3, h2 e gerente. O roteador de cada grupo roda em r1, r2 e r3. A especificação é a referência de tudo o que está aqui; este arquivo só mostra por onde começar.

## Requisitos

Docker Engine 28 ou mais recente, com Docker Compose 2.36 ou mais recente. No Windows e no macOS, o Docker Desktop atual. Todos os comandos rodam nesta pasta, e cada linha `docker ...` funciona igual no terminal do Linux e no `cmd` do Windows.

## Primeiros passos

1. Suba a rede. Na primeira vez, as imagens são construídas, o que leva alguns minutos:

   ```text
   docker compose up -d --build
   ```

2. Enquanto não houver o executável `roteador` em `roteador/`, as máquinas r1, r2 e r3 ficam no ar sem roteador, e `docker compose logs r1` diz isso. Já dá para observar a rede: `docker exec h1 ping -c 3 10.0.1.1` fica sem resposta, e `docker exec -it r1 tcpdump -n -e -i eth0` mostra as requisições ARP de h1.

3. Escreva o programa em `roteador/`, só com a biblioteca padrão da linguagem, sem pacotes de terceiros. Em Python, `roteador` pode ser o próprio script, começando por `#!/usr/bin/env python3`. Em C, C++ ou outra linguagem compilada, um `build.sh` gera o executável `roteador`. A cada mudança no código:

   ```text
   docker compose restart r1 r2 r3
   docker compose logs -f r1
   ```

4. Rode os testes automáticos, que mostram o que já funciona e o que falta, agrupados por parte do roteador:

   ```text
   docker compose run --rm testes
   ```

## O que há aqui

| Caminho | Conteúdo |
|---|---|
| `compose.yaml` | A topologia com o roteador do grupo, os serviços `testes` e `falha` e o perfil `painel` |
| `compose-kernel.yaml` | A mesma topologia com o encaminhamento do Linux, para o experimento |
| `configuracao/` | `r1.conf`, `r2.conf` e `r3.conf`, iguais aos da seção 3 da especificação |
| `roteador/` | O código do grupo e o `Dockerfile` da imagem dos roteadores |
| `quadros/` | Quadros de exemplo em hexadecimal, para `docker exec h1 injetar /quadros/ARQUIVO` |
| `capturas/` | Onde o `tcpdump` grava as capturas, vista em `/capturas` dentro das máquinas |
| `suporte/` | Imagens e programas do ambiente: máquinas, testes, falhas, isolamento das pontes e painel. Não precisa ser alterada |

A lista completa de comandos está na seção 12 da especificação, e a lista de verificação, na seção 13.
