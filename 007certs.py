#!/usr/bin/env python3
import os
import re
import subprocess
import json
import argparse
from datetime import datetime
from termcolor import colored

def unpack_apk(apk_file, quiet=False):
    output_dir = os.path.splitext(apk_file)[0]
    if not quiet:
        print(f"🔧 Descompactando APK: {apk_file}...")
    result = subprocess.run(["apktool", "d", apk_file, "-o", output_dir, "-f"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"❌ Erro ao descompactar APK: {result.stderr}")
        return None
    if not os.path.exists(output_dir):
        print(f"❌ Diretório de saída não encontrado após descompactação: {output_dir}")
        return None
    if not quiet:
        print(f"✅ APK descompactado em: {output_dir}")
    return output_dir

def find_files_by_extension(app_dir, extensions):
    matched_files = []
    for root, _, files in os.walk(app_dir):
        for file in files:
            if file.endswith(extensions):
                matched_files.append(os.path.join(root, file))
    return matched_files

def get_basename(file_path):
    return os.path.splitext(os.path.basename(file_path))[0].lower()

def validate_private_key(key_path):
    try:
        result = subprocess.run([
            "openssl", "rsa", "-in", key_path, "-check", "-noout"
        ], capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False

def validate_cert_key_pair(cert_path, key_path):
    try:
        pubkey_cert = subprocess.run([
            "openssl", "x509", "-in", cert_path, "-pubkey", "-noout"
        ], capture_output=True, text=True).stdout

        pubkey_priv = subprocess.run([
            "openssl", "rsa", "-in", key_path, "-pubout"
        ], capture_output=True, text=True).stdout

        return pubkey_cert.strip() == pubkey_priv.strip()
    except:
        return False

def analyze_text_cert_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if "PRIVATE KEY" in content:
                if validate_private_key(file_path):
                    return "🔐 Chave Privada Válida Detectada [CRITICAL]"
                else:
                    return "🔐 Chave Privada Inválida ou Corrompida [ALTO]"
            elif "PUBLIC KEY" in content or "BEGIN CERTIFICATE" in content:
                return "📜 Certificado Público Detectado [INFO]"
            else:
                return "❌ Arquivo relacionado a certificado (análise superficial) [POTENCIALMENTE IRRELEVANTE]"
    except Exception as e:
        return f"Erro ao ler: {e}"

def match_key_and_cert(certificates):
    pairs = []
    keys = [path for path, desc in certificates if "Privada" in desc]
    certs = [path for path, desc in certificates if "Certificado Público" in desc]
    for cert in certs:
        for key in keys:
            if validate_cert_key_pair(cert, key):
                pairs.append((cert, key))
    return pairs

def score_risk(certificates, pairs):
    score = 0
    for _, desc in certificates:
        if "CRITICAL" in desc:
            score += 3
        elif "ALTO" in desc:
            score += 2
        elif "INFO" in desc:
            score += 1
    score += len(pairs) * 2
    if score >= 12:
        return "CRÍTICO"
    elif score >= 7:
        return "ALTO"
    elif score >= 3:
        return "MÉDIO"
    else:
        return "BAIXO"

def locate_executable(app_dir):
    for root, _, files in os.walk(app_dir):
        for file in files:
            file_path = os.path.join(root, file)
            result = subprocess.run(["file", file_path], capture_output=True, text=True)
            if "Mach-O" in result.stdout or "ELF" in result.stdout:
                return file_path
    return None

def search_in_executable(executable):
    sha256_hashes = []
    der_references = []
    try:
        result = subprocess.run(["strings", executable], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if re.fullmatch(r"[A-Fa-f0-9]{64}", line):
                sha256_hashes.append(line)
            if ".der" in line:
                der_references.append(line)
    except Exception as e:
        sha256_hashes.append(f"Erro ao analisar executável: {e}")
    return sha256_hashes, der_references

def search_in_configs(app_dir):
    matches = []
    for root, _, files in os.walk(app_dir):
        for file in files:
            if file.endswith((".plist", ".json", ".xml")):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        if re.search(r"cert|hash|sha256|.der|public|private", content, re.IGNORECASE):
                            matches.append(file_path)
                except:
                    continue
    return matches

def advanced_checks(app_dir):
    results = []
    for root, _, files in os.walk(app_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if re.search(r"-----BEGIN (PRIVATE|CERTIFICATE|PUBLIC) KEY-----", content):
                        results.append(f"🔐 Chave ou Certificado hardcoded em: {file_path} [HIGH]")
                    if re.search(r"\b(SHA256withRSA|sha256|pinning|verify|trustManager)\b", content, re.IGNORECASE):
                        results.append(f"⚙️ Referência a pinning ou validação em: {file_path} [MODERADO-ALTO]")
                    if file == "AndroidManifest.xml":
                        if 'android:debuggable="true"' in content:
                            results.append("⚠️ Flag debuggable=true no AndroidManifest.xml [RISCO ALTO]")
                        if 'usesCleartextTraffic="true"' in content:
                            results.append("⚠️ Flag usesCleartextTraffic=true no AndroidManifest.xml [RISCO ALTO]")
            except:
                continue
    return results

def generate_report(results, output_format="txt", output_file="analysis_report", cert_analysis=None):
    if output_format == "json":
        with open(f"{output_file}.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif output_format == "html":
        with open(f"{output_file}.html", "w", encoding="utf-8") as f:
            f.write("<html><head><meta charset='utf-8'><title>007Certs Report</title></head><body>")
            f.write("<h1>007Certs - Relatório de Análise</h1>")
            for section, items in results.items():
                f.write(f"<h2>{section}</h2><ul>")
                for item in items:
                    f.write(f"<li>{item}</li>")
                f.write("</ul>")
            f.write("</body></html>")
    else:
        with open(f"{output_file}.txt", "w", encoding="utf-8") as f:
            for section, items in results.items():
                f.write(f"=== {section} ===\n")
                for item in items:
                    f.write(f"- {item}\n")

        with open(f"{output_file}_summary.txt", "w", encoding="utf-8") as f:
            f.write("""
🔎 What’s Next? 📌 What Do Your Findings Mean?

🟢 Safe Certificate: SHA-256 pinning is properly applied. All good. 😎
⚠️ Issue Detected: Exposed private keys or weak pinning. 🚨
😂 Funny Situation: You spent hours analyzing something irrelevant, but hey, it's all part of the game! 🎭

Resumo Técnico:
🔐 Chave Privada → Compromete segurança, pode levar a MitM ou spoofing → CRITICAL
📜 Certificado Público → Risco moderado (só se usado com pinning ou exposto) → Verificar se há chave privada junto
❌ Superficial → Talvez irrelevante, precisa inspeção manual → Pode ser descartado se vazio
⚙️ Validação / Pinning → Pode proteger ou prejudicar dependendo da implementação → Pode ser bypassado ou auditado
""")
            if cert_analysis:
                f.write("\n=== Certificados e Chaves ===\n")
                for line in cert_analysis["detected"]:
                    f.write(f"- {line}\n")
                f.write("\n=== Pares Identificados (validados via OpenSSL) ===\n")
                for cert, key in cert_analysis["pairs"]:
                    f.write(f"✔️ Certificado: {cert}\n🔐 Chave: {key}\n")
                f.write(f"\n🛡️ Score de Risco Final: {cert_analysis['risk']}\n")

def main():
    parser = argparse.ArgumentParser(description="007Certs - APK Certificate Analyzer")
    parser.add_argument("input", help="Arquivo APK ou diretório descompactado")
    parser.add_argument("--output-format", choices=["txt", "json", "html"], default="txt", help="Formato do relatório")
    parser.add_argument("--output-file", default="analysis_report", help="Nome do arquivo de relatório (sem extensão)")
    parser.add_argument("--quiet", action="store_true", help="Executa em modo silencioso")
    args = parser.parse_args()

    if not args.quiet:
        print("🚀 Iniciando análise com 007Certs...")

    app_dir = args.input
    if args.input.endswith(".apk"):
        app_dir = unpack_apk(args.input, args.quiet)
        if not app_dir:
            return

    if not args.quiet:
        print(f"📂 Varrendo diretório: {app_dir}")
        print("🔍 Procurando certificados (.crt, .pem, .key)...")

    results = {
        "DER Files": [],
        "Text Certificates": [],
        "Executavel": [],
        "Configuracoes": [],
        "Checks Avancados": []
    }

    cert_analysis = {"detected": [], "pairs": [], "risk": ""}
    certs_detected = []

    for file in find_files_by_extension(app_dir, ".der"):
        desc = "Arquivo .der detectado"
        results["DER Files"].append(f"{file} -> {desc}")

    for file in find_files_by_extension(app_dir, (".crt", ".pem", ".key")):
        desc = analyze_text_cert_file(file)
        colored_line = colored(f"{file} -> {desc}", "red" if "CRITICAL" in desc else "yellow" if "POTENCIALMENTE" in desc or "ALTO" in desc else "green")
        if not args.quiet:
            print(colored_line)
        results["Text Certificates"].append(f"{file} -> {desc}")
        certs_detected.append((file, desc))

    if not args.quiet:
        print("🧪 Validando pares de chave + certificado...")

    cert_analysis["detected"] = [f"{file} -> {desc}" for file, desc in certs_detected]
    cert_analysis["pairs"] = match_key_and_cert(certs_detected)
    cert_analysis["risk"] = score_risk(certs_detected, cert_analysis["pairs"])

    if not args.quiet:
        print("🔎 Buscando executáveis no diretório do APK...")

    exe = locate_executable(app_dir)
    if exe:
        hashes, refs = search_in_executable(exe)
        results["Executavel"].append(f"{exe} (Hashes SHA-256 encontrados: {len(hashes)}, Referencias a .der: {len(refs)})")
        results["Executavel"].extend(hashes + refs)

    if not args.quiet:
        print("📂 Varredura de arquivos de configuração...")

    results["Configuracoes"] = search_in_configs(app_dir)
    results["Checks Avancados"] = advanced_checks(app_dir)

    if not args.quiet:
        print("📊 Gerando relatório final...")

    generate_report(results, args.output_format, args.output_file, cert_analysis)

    if not args.quiet:
        print(f"\n✅ Relatório gerado: {args.output_file}.{args.output_format}")
        print(f"📄 Resumo salvo em: {args.output_file}_summary.txt")
        print(f"🛡️ Score Final de Risco: {cert_analysis['risk']}")
        if cert_analysis['pairs']:
            print("\n🔗 Pares Certificado + Chave Privada Detectados:")
            for cert, key in cert_analysis['pairs']:
                print(f"✔️ Certificado: {cert}\n🔐 Chave: {key}\n")


if __name__ == "__main__":
    main()
