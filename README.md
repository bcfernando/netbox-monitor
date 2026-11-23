# NetBox Monitor

Monitoramento nativo estilo **Zabbix + Grafana** para o **NetBox 4.x**.

O NetBox Monitor transforma o inventário do NetBox em uma central de monitoramento
de switches: coleta ICMP e SNMP diretamente pelo NetBox, armazena o histórico de
métricas e exibe latência, CPU, memória, tráfego, VLANs e loops STP em dashboards
integrados à interface do NetBox — sem precisar de Zabbix, Grafana ou Prometheus.

## Recursos

- **Coleta Paralela ICMP (Latência, Jitter e Perda de Pacotes) + SNMPv1/v2c**:
  - Ping ICMP com `count=3`, `interval=0.15s` e `timeout=1s`, calculando latência
    média, **perda de pacotes (%)** e **jitter (ms)**, salvos em
    `hardware_metrics['ping_quality'] = {'packet_loss': ..., 'jitter_ms': ...}`.
  - SNMPv1/v2c para coleta de `sysDescr`, uptime, CPU, memória, interfaces, VLANs,
    PoE, sensores de hardware, LLDP/CDP e loop STP.
  - Coleta paralela em lote (até 16 workers) e coleta sob demanda por dispositivo.
- **Cálculo de banda em Mbps** por interface, a partir dos contadores
  `ifHCInOctets` / `ifHCOutOctets` (com fallback para os contadores 32 bits).
- **Painel Frontal Dinâmico por Fabricante** (Aruba, HPE, Cisco, MikroTik,
  Ubiquiti e genérico), com portas físicas 1–48 e SFPs 49–52.
- **Detecção Inteligente de Loop STP** via `dot1dStpPortState` e mudanças de topologia.
- **Mapeamento de VLANs** via `dot1qVlanStaticName` e `dot1qPvid`, além da
  **Sincronização de Interfaces/Cabos LLDP no NetBox** (rota
  `POST /plugins/monitor/topology/sync-cables/` com o botão "🔗 Gravar Cabos LLDP").
- **Topologia Automática por Rack** (Modo Claro/Escuro + Exportar PDF).
- **Modo TV NOC Ao Vivo** (estilo Centreon/Grafana sem recarregar a página).
- **Cálculo de SLA (7d)** por dispositivo.
- **Exportação CSV** e **Alertas via Telegram/Webhook**.

### Coleta ICMP e qualidade de link

A coleta ICMP utiliza três pacotes por disparo (`count=3`, `interval=0.15s`,
`timeout=1`) e expõe no último registro de `DeviceMetric`:

- `latency_ms`: latência média (RTT) em milissegundos;
- `packet_loss`: percentual de perda de pacotes (0 a 100);
- `jitter_ms`: jitter médio (variação) em milissegundos.

A tela de dispositivos destaca a **perda** em vermelho quando `packet_loss > 0`.

## Requisitos

- NetBox **4.x**
- Python **3.10+**
- `icmplib>=3.0.4`
- `pysnmp-lextudio>=6.0.0`

## Instalação

1. Instale o plugin no ambiente do NetBox:

   ```bash
   pip install netbox-monitor
   ```

   Para desenvolvimento, use a instalação editável:

   ```bash
   pip install -e /caminho/para/netbox-monitor
   ```

2. Habilite o plugin em `configuration.py`:

   ```python
   PLUGINS = ['netbox_monitor']
   ```

3. Aplique as migrações:

   ```bash
   python manage.py migrate
   ```

4. Reinicie o NetBox.

## Uso

### Custom Field `snmp_community`

O plugin usa a community SNMP definida por dispositivo. Crie um Custom Field
do tipo **Text** com o nome exato `snmp_community` em **Customization → Custom
Fields** e vincule-o ao modelo **Device**.

- Se o campo estiver preenchido, o valor é usado na coleta SNMP.
- Se estiver vazio ou ausente, o plugin usa `public`.

Exemplo via API:

```bash
curl -X POST "$NETBOX_URL/api/extras/custom-fields/" \
  -H "Authorization: Token $NETBOX_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"object_types": ["dcim.device"], "name": "snmp_community", "label": "SNMP Community", "type": "text"}'
```

### Filtro de dispositivos

Por padrão, todos os dispositivos com IP primário (`primary_ip4` ou `primary_ip6`)
são monitorados. Para restringir a coleta, crie a tag `monitorar` e aplique-a aos
dispositivos desejados.

### Páginas

- **Monitoramento** (`/plugins/monitor/`): visão geral de todos os dispositivos,
  com total, online, offline, latência, **perda de pacotes (%)** e **jitter (ms)**,
  além do botão de coleta.
- **Device → aba Monitoramento**: métricas, gráficos, VLANs, status STP, qualidade
  ICMP (latência, perda e jitter) e painel frontal do switch.
- **Topologia** (`/plugins/monitor/topology/`): topologia por LLDP/CDP com botão
  **🔗 Gravar Cabos LLDP** (`POST /plugins/monitor/topology/sync-cables/`) que cria
  automaticamente os `Cable` no NetBox entre dispositivos vizinhos detectados.
- **Modo TV** (`/plugins/monitor/tv/`): dashboard NOC ao vivo estilo Centreon/Grafana
  com gráficos, gauges e disponibilidade por minuto, atualizando sem recarregar a página.

### Alertas

Alertas de latência alta, offline, loop STP e queda de uplink são enviados via
webhook (Telegram/Discord/Slack/n8n) configurado em **Settings → NetBox Monitor**.

### Painel frontal

O painel é gerado a partir das interfaces retornadas pelo SNMP. Interfaces
virtuais de agregação e gerenciamento — `lo`, `loopback`, `vlan`, `null`, `mgmt`,
`trk` (ex.: `TRK1`, `TRK2`) e `port-channel` (ex.: `Port-channel1`) — são ocultadas
(case-insensitive), garantindo que apenas as portas físicas (1–48) e os SFPs
(49–52) apareçam no desenho.

## Estrutura do projeto

```text
netbox-monitor/
├── netbox_monitor/
│   ├── __init__.py          # NetBoxMonitorConfig
│   ├── jobs.py              # Coleta ICMP/SNMP e DeviceMonitorJob
│   ├── models.py            # DeviceMetric
│   ├── navigation.py        # Menu "Monitoramento"
│   ├── template_content.py  # Card de monitoramento em Device
│   ├── urls.py              # Rotas do plugin (/plugins/monitor/)
│   ├── views.py             # Monitor, DeviceMonitor e coleta sob demanda
│   ├── migrations/
│   └── templates/netbox_monitor/
├── pyproject.toml
├── LICENSE
└── README.md
```

## Desenvolvimento

O plugin é instalado em modo editável na imagem `Dockerfile-Plugins` do
`netbox-docker` e montado como bind mount em `/opt/netbox-monitor`, então
edições locais refletem imediatamente no container. Reinicie o serviço NetBox
após alterar `views.py`, `jobs.py` ou configurações:

```bash
docker compose restart netbox
```

## Licença

Distribuído sob a licença **Apache 2.0**. Veja [LICENSE](LICENSE).
