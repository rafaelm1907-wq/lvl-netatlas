# LVL - NetAtlas

Geomapa operacional para provedores: inventário do NetBox, telemetria do Zabbix, enlaces, CTOs, POPs, permissões e licenciamento.

## Instalação em um novo cliente

O instalador pede interativamente o endereço e token do NetBox, os dados de acesso somente-leitura ao banco do Zabbix e a senha inicial do Superadmin. Dados de clientes não fazem parte deste repositório.

No servidor novo, com PostgreSQL/PostGIS, Git e Python 3 instalados:

```bash
git clone URL_DO_REPOSITORIO_GIT
cd netatlas
sudo ./install.sh URL_DO_REPOSITORIO_GIT
```

O serviço é criado em `netatlas.service`, escuta na porta `20050` e as credenciais ficam protegidas em `/etc/netatlas/netatlas.env` (`0600`).

## Pré-requisitos

- Ubuntu/Debian com PostgreSQL e extensão PostGIS.
- NetBox acessível com token de API que possa criar/atualizar os registros do NetAtlas.
- Banco MySQL/MariaDB do Zabbix acessível com usuário de leitura.
- HTTPS para o servidor de licenças em produção.

## Segurança

Nunca envie `.env`, `/etc/netatlas/netatlas.env`, tokens, senhas ou bancos de dados ao Git. O arquivo `.env.example` é apenas um modelo sem credenciais.
