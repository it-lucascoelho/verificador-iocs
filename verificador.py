import os

import requests
from dotenv import load_dotenv

load_dotenv()

URL = "https://api.abuseipdb.com/api/v2/check"


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
    dados = consultar_ip("8.8.8.8")
    print(f"IP: {dados['ipAddress']}")
    print(f"Pontuação de abuso: {dados['abuseConfidenceScore']}%")
    print(f"Total de denúncias: {dados['totalReports']}")
    print(f"País: {dados['countryCode']}")
    print(f"Provedor: {dados['isp']}")