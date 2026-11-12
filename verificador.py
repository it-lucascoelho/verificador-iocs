import ipaddress
import os

import requests
from dotenv import load_dotenv

load_dotenv()

URL = "https://api.abuseipdb.com/api/v2/check"


class ErroConsulta(Exception):
    """Falha em um IOC específico; dá para seguir para o próximo."""


class ErroFatal(Exception):
    """Falha que impede continuar (chave inválida, limite excedido)."""


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
        raise ErroFatal("chave não encontrada; crie o arquivo .env (veja .env.example)")

    try:
        resposta = requests.get(
            URL,
            headers={"Key": chave, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
    except requests.exceptions.Timeout:
        raise ErroConsulta("tempo esgotado")
    except requests.exceptions.ConnectionError:
        raise ErroConsulta("sem conexão com a internet")

    if resposta.status_code in (401, 403):
        raise ErroFatal("chave de API inválida")
    if resposta.status_code == 429:
        raise ErroFatal("limite de consultas excedido")
    if resposta.status_code == 422:
        raise ErroConsulta("IP rejeitado pela API")
    if resposta.status_code != 200:
        raise ErroConsulta(f"resposta inesperada (código {resposta.status_code})")

    return resposta.json()["data"]


if __name__ == "__main__":
    for ioc in ler_iocs("amostras/iocs.txt"):
        if not ip_valido(ioc):
            print(f"{ioc}: IGNORADO (não é um IP válido)")
            continue

        try:
            dados = consultar_ip(ioc)
        except ErroFatal as erro:
            print(f"ERRO FATAL: {erro}. Encerrando.")
            break
        except ErroConsulta as erro:
            print(f"{ioc}: ERRO ({erro})")
            continue

        pais = dados.get("countryCode") or "desconhecido"
        provedor = dados.get("isp") or "desconhecido"
        print(
            f"{ioc}: pontuação {dados['abuseConfidenceScore']}% | "
            f"{dados['totalReports']} denúncias | {pais} | {provedor}"
        )