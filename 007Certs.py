import os
import re
import subprocess

def find_der_files(app_dir):
    """Localiza arquivos .der no diretório."""
    der_files = []
    for root, _, files in os.walk(app_dir):
        for file in files:
            if file.endswith(".der"):
                der_files.append(os.path.join(root, file))
    return der_files

def analyze_der_file(file_path):
    """Analisa o conteúdo do arquivo .der."""
    try:
        # Verifica se contém chave privada
        result = subprocess.run(
            ["openssl", "rsa", "-inform", "der", "-in", file_path, "-check"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return "Chave Privada"
        
        # Verifica se contém certificado público
        result = subprocess.run(
            ["openssl", "x509", "-inform", "der", "-in", file_path, "-noout"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            # Extrai o hash SHA-256
            hash_result = subprocess.run(
                ["openssl", "x509", "-inform", "der", "-in", file_path, "-fingerprint", "-sha256", "-noout"],
                capture_output=True,
                text=True
            )
            sha256_hash = re.search(r"Fingerprint=(.*)", hash_result.stdout)
            return f"Certificado Público | SHA-256: {sha256_hash.group(1).replace(':', '')}" if sha256_hash else "Certificado Público"
        
        return "Formato Desconhecido"
    except Exception as e:
        return f"Erro ao analisar: {e}"

def locate_executable(app_dir):
    """Localiza o executável no diretório."""
    for root, _, files in os.walk(app_dir):
        for file in files:
            file_path = os.path.join(root, file)
            result = subprocess.run(["file", file_path], capture_output=True, text=True)
            if "Mach-O" in result.stdout or "ELF" in result.stdout:
                return file_path
    return None

def search_in_executable(executable):
    """Procura por hashes SHA-256 e referências a arquivos .der no executável."""
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
        print(f"Erro ao analisar executável: {e}")
    return sha256_hashes, der_references

def search_in_configs(app_dir):
    """Procura por referências em arquivos de configuração."""
    matches = []
    for root, _, files in os.walk(app_dir):
        for file in files:
            if file.endswith((".plist", ".json", ".xml")):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        if re.search(r"cert|hash|sha256|.der", content, re.IGNORECASE):
                            matches.append(file_path)
                except Exception as e:
                    print(f"Erro ao analisar arquivo de configuração {file}: {e}")
    return matches

def main(app_dir):
    output_file = "analysis_report.txt"
    with open(output_file, "w") as report:
        report.write("--------------------------------------------\n")
        report.write("Análise Completa de Certificados no Aplicativo\n")
        report.write("--------------------------------------------\n")
        
        # Passo 1: Verificar arquivos .der
        report.write(">> Passo 1: Verificando arquivos .der no diretório...\n")
        der_files = find_der_files(app_dir)
        if not der_files:
            report.write("Nenhum arquivo .der encontrado.\n")
        else:
            for der_file in der_files:
                result = analyze_der_file(der_file)
                report.write(f"Arquivo: {der_file}\n  -> {result}\n")
        
        # Passo 2: Localizar o binário principal
        report.write(">> Passo 2: Localizando binário principal...\n")
        executable = locate_executable(app_dir)
        if executable:
            report.write(f"Executável identificado: {executable}\n")
            sha256_hashes, der_references = search_in_executable(executable)
            report.write("  -> Hashes SHA-256 encontrados no executável:\n")
            report.write("\n".join(sha256_hashes) + "\n")
            report.write("  -> Referências a arquivos .der no executável:\n")
            report.write("\n".join(der_references) + "\n")
        else:
            report.write("Nenhum executável encontrado.\n")
        
        # Passo 3: Verificar arquivos de configuração
        report.write(">> Passo 3: Verificando arquivos de configuração...\n")
        config_matches = search_in_configs(app_dir)
        if config_matches:
            report.write("Referências encontradas nos seguintes arquivos:\n")
            report.write("\n".join(config_matches) + "\n")
        else:
            report.write("Nenhuma referência encontrada em arquivos de configuração.\n")
        
        report.write("--------------------------------------------\n")
        report.write("Análise Completa Finalizada.\n")
    
    print(f"Análise completa. Confira o relatório: {output_file}")

if __name__ == "__main__":
    import sys
    app_directory = sys.argv[1] if len(sys.argv) > 1 else "./"
    main(app_directory)
