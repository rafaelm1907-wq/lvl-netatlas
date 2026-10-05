# LVL - NetAtlas

Geomapa operacional para provedores: inventário do NetBox, telemetria do Zabbix, enlaces, CTOs, POPs, permissões e licenciamento.

## Instalação em um novo cliente

O instalador pede interativamente o endereço e token do NetBox, os dados de acesso somente-leitura ao banco do Zabbix, a senha inicial do Superadmin e, opcionalmente, a URL/token somente leitura do Gerenciador de OLTs. Dados de clientes não fazem parte deste repositório.

No servidor novo, com PostgreSQL/PostGIS, Git e Python 3 instalados:

```bash
git clone https://github.com/rafaelm1907-wq/lvl-netatlas.git
cd lvl-netatlas
sudo ./install.sh
```

O serviço é criado em `netatlas.service`, escuta na porta `20050` e as credenciais ficam protegidas em `/etc/netatlas/netatlas.env` (`0600`).

## Pré-requisitos

- Ubuntu/Debian com PostgreSQL e extensão PostGIS.
- NetBox acessível com token de API que possa criar/atualizar os registros do NetAtlas.
- Banco MySQL/MariaDB do Zabbix acessível com usuário de leitura.
- HTTPS para o servidor de licenças em produção.

## Integração com o Gerenciador de OLTs

Quando uma CTO está em um enlace conectado a uma interface GPON, o NetAtlas correlaciona o host do Zabbix com a OLT pelo IP de gerenciamento. Um splitter pode ser nomeado e dividido em saídas para clientes, continuação do enlace ou reserva. As ONTs podem ser pesquisadas por nome, serial, ID ou VLAN e exibem status e potência RX.

O gerenciador deve disponibilizar as rotas somente leitura `/api/integration/olts` e `/api/integration/onts`, protegidas por Bearer token. Configure `OLT_MANAGER_URL` e `OLT_MANAGER_TOKEN` em `/etc/netatlas/netatlas.env`. As associações físicas são persistidas pelo NetAtlas e resumidas no registro da CTO no NetBox; a telemetria permanece no gerenciador de OLTs.

## Segurança

Nunca envie `.env`, `/etc/netatlas/netatlas.env`, tokens, senhas ou bancos de dados ao Git. O arquivo `.env.example` é apenas um modelo sem credenciais.
