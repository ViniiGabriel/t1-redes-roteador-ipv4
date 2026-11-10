#!/usr/bin/env python3
import sys
from config import ler_configuracao

def main():
    config = []
    if sys.argv < 2 :
        print("Uso: python3 roteador.py <arquivo_de_configuracao>")
        sys.exit(1)
    config = ler_configuracao(sys.argv)
