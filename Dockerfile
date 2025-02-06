# Usando uma imagem base do Python
FROM python:3.11-slim

# Atualiza o sistema e instala ferramentas necessárias
RUN apt-get update && apt-get install -y \
    openssl \
    file \
    binutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Define o diretório de trabalho
WORKDIR /app

# Copia o código da ferramenta para dentro do contêiner
COPY . .

# Instala as dependências Python, se houver (verificar se há um requirements.txt)
# Caso contrário, pule esta etapa
# RUN pip install -r requirements.txt

# Permite passar argumentos ao executar o contêiner
ENTRYPOINT ["python", "007Certs.py"]
CMD []
