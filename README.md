# Repository Delivery 2

-----------------------
115697 - Para recurso
- Todos comandos funcionais - Desennvolvimento dos comandos que faltavam
- Aplicacao de um challenge para certificar que estamos a enviar request para o repositorio
- uso de assinatura para confirmar que ao cliente que é uma resposta do cliente
- limitacao do numero de requests por minuto com base no endereco IP
- Proibicao da repeticao de comandos com payload que pode ser roubado, com uso de timestamps que estao encriptados e só o repositorio tem acesso
- informacoes cruciais da sessao so podem ser acessadas pelo repositorio
- O challenge para o repositorio é sempre feito antes do envio de qualquer informacao
- encriptacao de toda a informacao trocada, independentemente do nivel de importancia da informacao
- Proibicao ao tentar assumir o lugar de Manager por parte de um subject qualquer
-----------------------

## Alunos
**Nome**: Shelton Lázio Agostinho
**Numero Mecanografico**: 115697

**Nome**: Giovanni Pereira Santos
**Numero Mecanografico**: 115637

## Funcionalidades Implementadas
1. Os comandos que não haviam sido terminados da delivery1
2. Gestao de ROLES de organizacoes e documentos
3. Gestao de permissoes em organizacoes e documentos
4. Dados persistentes

> A explicacao da ideia será na proxima delivery e potenciais ajustes


## Como executar
1. Crie um virtual environment:
```bash
python3 -m venv venv
```

2. Active o virtual environment (precisa de repetir este passo sempre que começar uma nossa sessão/terminal):
```bash
source venv/bin/activate
```

3. Instale os requisitos:
```bash
pip install -r requirements.txt
```

4. Endereço:
```bash
cd src
export REP_ADDRESS="127.0.0.1:5000"
```
5. Chave pública do repositório:
```bash
export REP_PUB_KEY="./repo_public_key.pem"
```

6. Iniciar a base de dados
```bash
docker compose up -d
```

7. Construir as tabelas
```bash
python3 models/newdb.py
```

8. Em outro terminal em ./src
```bash
python3 src/api/repository.py
```

## No primeiro Terminal, em ./delivery2/src
### Para testes: ./tests.sh
### Pode executar qualquer outro comando

> Nota: para permissoes - $ chmod u+x tests.sh e $ chmod +x rep_*