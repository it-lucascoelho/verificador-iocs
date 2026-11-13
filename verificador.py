import argparse
import csv
import ipaddress
import json
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
    """Lê IOCs de um .txt (um por linha) ou IPs de um relatório .json do analisador."""
    if caminho.endswith(".json"):
        with open(caminho, "r", encoding="utf-8") as f:
            return [item["ip"] for item in json.load(f)]

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

LIMITE_MALICIOSO = 75
LIMITE_SUSPEITO = 25


def classificar(pontuacao):
    if pontuacao >= LIMITE_MALICIOSO:
        return "MALICIOSO"
    if pontuacao >= LIMITE_SUSPEITO:
        return "SUSPEITO"
    return "LIMPO"


def verificar_iocs(iocs):
    """Consulta cada IOC e devolve uma lista de resultados (um dicionário por IOC)."""
    resultados = []
    for ioc in iocs:
        if not ip_valido(ioc):
            resultados.append({"ioc": ioc, "status": "IGNORADO", "erro": "não é um IP válido"})
            continue

        try:
            dados = consultar_ip(ioc)
        except ErroFatal as erro:
            print(f"ERRO FATAL: {erro}. Encerrando.")
            break
        except ErroConsulta as erro:
            resultados.append({"ioc": ioc, "status": "ERRO", "erro": str(erro)})
            continue

        pontuacao = dados["abuseConfidenceScore"]
        resultados.append({
            "ioc": ioc,
            "status": classificar(pontuacao),
            "pontuacao": pontuacao,
            "denuncias": dados["totalReports"],
            "pais": dados.get("countryCode") or "desconhecido",
            "provedor": dados.get("isp") or "desconhecido",
        })
    return resultados


def imprimir(resultados):
    for r in resultados:
        if "pontuacao" in r:
            print(f"[{r['status']}] {r['ioc']} | pontuação {r['pontuacao']}% | "
                  f"{r['denuncias']} denúncias | {r['pais']} | {r['provedor']}")
        else:
            print(f"[{r['status']}] {r['ioc']} | {r['erro']}")

    total = len(resultados)
    maliciosos = sum(r["status"] == "MALICIOSO" for r in resultados)
    suspeitos = sum(r["status"] == "SUSPEITO" for r in resultados)
    print(f"\nResumo: {total} IOCs processados | {maliciosos} maliciosos | {suspeitos} suspeitos")


def salvar_json(resultados, caminho):
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(resultados, f, indent=2, ensure_ascii=False)


def salvar_csv(resultados, caminho):
    campos = ["ioc", "status", "pontuacao", "denuncias", "pais", "provedor", "erro"]
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=campos, restval="")
        escritor.writeheader()
        escritor.writerows(resultados)


def main():
    parser = argparse.ArgumentParser(
        description="Verifica a reputação de IPs (IOCs) usando a API do AbuseIPDB."
    )
    parser.add_argument(
        "entrada",
        help="arquivo .txt (um IP por linha) ou .json gerado pelo analisador-logs",
    )
    parser.add_argument("--saida", help="arquivo de saída (.json ou .csv)")
    args = parser.parse_args()

    resultados = verificar_iocs(ler_iocs(args.entrada))
    imprimir(resultados)

    if args.saida:
        if args.saida.endswith(".json"):
            salvar_json(resultados, args.saida)
        else:
            salvar_csv(resultados, args.saida)
        print(f"Resultado salvo em {args.saida}")


if __name__ == "__main__":
    main()