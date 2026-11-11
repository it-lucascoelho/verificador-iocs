import ipaddress
import os

import requests
from dotenv import load_dotenv

load_dotenv()

URL = "https://api.abuseipdb.com/api/v2/check"


def ler_iocs(caminho):
    """Lê o arquivo e devolve uma lista de textos, ignorando vazias e comentários."""
    iocs = []
    with open(caminho, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if linha and not linha.startswith("#"):
                iocs.append(linha)
    return iocs


def ip_valido(texto):
    try:
        ipaddress.ip_address(texto)
        return True
    except ValueError:
        return False


def consultar_ip(ip):
    chave = os.getenv("ABUSEIPDB_API_KEY")
    if not chave:
        raise SystemExit("Chave não encontrada. Crie o arquivo .env (veja .env.example).")

    resposta = requests.get(
        URL,
        headers={"Key": chave, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,
    )
    resposta.raise_for_status()
    return resposta.json()["data"]


if __name__ == "__main__":
    for ioc in ler_iocs("amostras/iocs.txt"):
        if not ip_valido(ioc):
            print(f"{ioc}: IGNORADO (não é um IP válido)")
            continue
        dados = consultar_ip(ioc)
        print(
            f"{ioc}: pontuação {dados['abuseConfidenceScore']}% | "
            f"{dados['totalReports']} denúncias | {dados['countryCode']} | {dados['isp']}"
        )