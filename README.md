# NetBox Monitor

Monitoramento nativo estilo **Zabbix + Grafana** para o **NetBox 4.x**.

O NetBox Monitor transforma o inventário do NetBox em uma central de monitoramento
de switches: coleta ICMP e SNMP diretamente pelo NetBox, armazena o histórico de
métricas e exibe latência, CPU, memória, tráfego, VLANs e loops STP em dashboards
integrados à interface do NetBox — sem precisar de Zabbix, Grafana ou Prometheus.

## Recursos

- **Ping ICMP** por dispositivo, com latência (RTT) e status online/offline.
- **SNMPv1/v2c** para coleta de `sysDescr`, uptime, CPU e memória.
- **Cálculo de banda em Mbps** por interface, a partir dos contadores
  `ifHCInOctets` / `ifHCOutOctets` (com fallback para os contadores 32 bits).
- **Painel frontal dinâmico por fabricante** (Aruba, HPE, Cisco, MikroTik,
  Ubiquiti e genérico), com portas físicas 1–48 e SFPs 49–52.
- **Detecção de loop STP** via `dot1dStpPortState` e mudanças de topologia.
- **Mapeamento de VLANs** via `dot1qVlanStaticName` e `dot1qPvid`.
- **Histórico de métricas** em `DeviceMetric` e gráficos de latência, CPU e memória.
- **Jobs agendados** (`DeviceMonitorJob`, a cada 5 minutos) e coleta sob demanda.

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
  com total, online, offline e botão de coleta.
- **Device → aba Monitoramento**: métricas, gráficos, VLANs, status STP e painel
  frontal do switch.

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
