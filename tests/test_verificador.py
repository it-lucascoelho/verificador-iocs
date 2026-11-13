import json

import verificador
from verificador import (
    ErroConsulta,
    classificar,
    ip_valido,
    ler_iocs,
    salvar_csv,
    verificar_iocs,
)


# --- classificar ---

def test_classifica_limpo():
    assert classificar(0) == "LIMPO"
    assert classificar(24) == "LIMPO"


def test_classifica_suspeito():
    assert classificar(25) == "SUSPEITO"
    assert classificar(74) == "SUSPEITO"


def test_classifica_malicioso():
    assert classificar(75) == "MALICIOSO"
    assert classificar(100) == "MALICIOSO"


# --- ip_valido ---

def test_ip_valido():
    assert ip_valido("8.8.8.8")
    assert not ip_valido("999.999.1.1")
    assert not ip_valido("isso-nao-e-um-ip")


# --- ler_iocs ---

def test_ler_iocs_ignora_comentarios_e_linhas_vazias(tmp_path):
    arquivo = tmp_path / "iocs.txt"
    arquivo.write_text("# comentário\n\n8.8.8.8\n  1.1.1.1  \n", encoding="utf-8")
    assert ler_iocs(str(arquivo)) == ["8.8.8.8", "1.1.1.1"]


def test_ler_iocs_de_relatorio_json(tmp_path):
    arquivo = tmp_path / "suspeitos.json"
    arquivo.write_text(json.dumps([{"ip": "203.0.113.50"}]), encoding="utf-8")
    assert ler_iocs(str(arquivo)) == ["203.0.113.50"]


# --- verificar_iocs (sem chamar a API de verdade) ---

def test_verificar_classifica_resultado(monkeypatch):
    def api_falsa(ip):
        return {"abuseConfidenceScore": 90, "totalReports": 5,
                "countryCode": "XX", "isp": "Teste"}

    monkeypatch.setattr(verificador, "consultar_ip", api_falsa)
    resultado = verificar_iocs(["203.0.113.5"])
    assert resultado[0]["status"] == "MALICIOSO"
    assert resultado[0]["pontuacao"] == 90


def test_verificar_ignora_ip_invalido_sem_chamar_a_api(monkeypatch):
    def api_nao_deveria_ser_chamada(ip):
        raise AssertionError("a API não deveria ser chamada")

    monkeypatch.setattr(verificador, "consultar_ip", api_nao_deveria_ser_chamada)
    resultado = verificar_iocs(["isso-nao-e-um-ip"])
    assert resultado[0]["status"] == "IGNORADO"


def test_verificar_registra_erro_e_continua(monkeypatch):
    def api_com_falha(ip):
        raise ErroConsulta("tempo esgotado")

    monkeypatch.setattr(verificador, "consultar_ip", api_com_falha)
    resultado = verificar_iocs(["8.8.8.8", "1.1.1.1"])
    assert [r["status"] for r in resultado] == ["ERRO", "ERRO"]


# --- salvar_csv ---

def test_salvar_csv_cria_cabecalho_e_linhas(tmp_path):
    arquivo = tmp_path / "saida.csv"
    salvar_csv([{"ioc": "8.8.8.8", "status": "LIMPO", "pontuacao": 0}], str(arquivo))
    linhas = arquivo.read_text(encoding="utf-8").splitlines()
    assert linhas[0].startswith("ioc,status")
    assert "8.8.8.8" in linhas[1]