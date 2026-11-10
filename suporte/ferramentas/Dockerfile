# Imagem dos serviços testes e falha: cliente Docker e Python.
# Os programas ficam em suporte/ferramentas/ e são montados em /suporte.
FROM docker:29-cli
RUN apk add --no-cache python3 iproute2
WORKDIR /suporte
ENV PYTHONDONTWRITEBYTECODE=1
