import asyncio

from dcim.models import Device
from netbox.jobs import JobRunner, system_job

from .models import DeviceMetric

OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0'
OID_SYS_UPTIME = '1.3.6.1.2.1.1.3.0'
OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2'
OID_IF_OPER_STATUS = '1.3.6.1.2.1.2.2.1.8'
OID_IF_IN_OCTETS = '1.3.6.1.2.1.2.2.1.10'
OID_IF_OUT_OCTETS = '1.3.6.1.2.1.2.2.1.16'
OID_IF_HC_IN_OCTETS = '1.3.6.1.2.1.31.1.1.1.6'
OID_IF_HC_OUT_OCTETS = '1.3.6.1.2.1.31.1.1.1.10'
OID_HR_PROCESSOR_LOAD = '1.3.6.1.2.1.25.3.3.1.2'
OID_HR_STORAGE_TABLE = '1.3.6.1.2.1.25.2.3.1'
OID_HR_STORAGE_TYPE_RAM = '1.3.6.1.2.1.25.2.1.2'
OID_DOT1Q_VLAN_STATIC_NAME = '1.3.6.1.2.1.17.7.1.4.3.1.1'
OID_DOT1Q_PVID = '1.3.6.1.2.1.17.7.1.4.5.1.1'
OID_DOT1D_STP_TOP_CHANGES = '1.3.6.1.2.1.17.2.4.0'
OID_DOT1D_STP_TIME_SINCE_TOP_CHANGE = '1.3.6.1.2.1.17.2.3.0'
OID_DOT1D_STP_PORT_STATE = '1.3.6.1.2.1.17.2.15.1.3'

STP_PORT_STATES = {
    1: 'DISABLED',
    2: 'BLOCKING',
    3: 'LISTENING',
    4: 'LEARNING',
    5: 'FORWARDING',
    6: 'BROKEN',
}
STP_ALERT_STATES = ('BLOCKING', 'BROKEN')
STP_RECENT_CHANGE_HUNDREDTHS = 30000

SNMP_TIMEOUT = 4
SNMP_RETRIES = 1
SNMP_MAX_INTERFACES = 64
SNMP_MAX_PROCESSORS = 256
SNMP_MAX_STORAGE_ENTRIES = 2000
SNMP_MAX_VLANS = 512
SNMP_MAX_STP_PORTS = 512


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


async def _snmp_walk(engine, auth, target, context, base_oid, limit):
    from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, walkCmd

    values = {}
    async for error_indication, error_status, _, var_binds in walkCmd(
        engine,
        auth,
        target,
        context,
        ObjectType(ObjectIdentity(base_oid)),
        lexicographicMode=False,
    ):
        if error_indication or error_status:
            break
        for name, value in var_binds:
            values[str(name)] = value
            if len(values) >= limit:
                return values
    return values


async def _snmp_get(engine, auth, target, context, oid):
    from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, getCmd

    error_indication, error_status, _, var_binds = await getCmd(
        engine,
        auth,
        target,
        context,
        ObjectType(ObjectIdentity(oid)),
    )
    if error_indication:
        raise RuntimeError(str(error_indication))
    if error_status:
        raise RuntimeError(error_status.prettyPrint())
    if not var_binds:
        return None
    return var_binds[0][1]


def _oid_index(oid):
    return oid.rsplit('.', 1)[-1]


async def _collect_vlans(engine, auth, target, context, index_to_name):
    vlans_summary = []
    try:
        vlan_names = await _snmp_walk(
            engine, auth, target, context, OID_DOT1Q_VLAN_STATIC_NAME, SNMP_MAX_VLANS
        )
    except Exception:
        vlan_names = {}

    pvid_by_index = {}
    try:
        pvid_values = await _snmp_walk(
            engine, auth, target, context, OID_DOT1Q_PVID, SNMP_MAX_VLANS
        )
        for oid, value in pvid_values.items():
            vlan_id = _to_int(value)
            if vlan_id is None:
                continue
            pvid_by_index[_oid_index(oid)] = vlan_id
    except Exception:
        pvid_by_index = {}

    names = {}
    for oid, value in vlan_names.items():
        vlan_id = _to_int(_oid_index(oid))
        if vlan_id is not None:
            names[vlan_id] = str(value)[:64]

    for vlan_id in sorted(set(names) | set(pvid_by_index.values())):
        ports = [
            index_to_name[index]
            for index, pvid in pvid_by_index.items()
            if pvid == vlan_id and index in index_to_name
        ]
        vlans_summary.append({
            'vlan_id': vlan_id,
            'name': names.get(vlan_id) or f'VLAN {vlan_id}',
            'ports': sorted(set(ports), key=lambda name: name.lower()),
        })
    return vlans_summary, pvid_by_index


async def _collect_loop_status(engine, auth, target, context, index_to_name):
    top_changes = None
    time_since_top_change = None
    port_states = {}

    try:
        value = await _snmp_get(engine, auth, target, context, OID_DOT1D_STP_TOP_CHANGES)
        top_changes = _to_int(value)
    except Exception:
        top_changes = None

    try:
        value = await _snmp_get(
            engine, auth, target, context, OID_DOT1D_STP_TIME_SINCE_TOP_CHANGE
        )
        time_since_top_change = _to_int(value)
    except Exception:
        time_since_top_change = None

    try:
        state_values = await _snmp_walk(
            engine, auth, target, context, OID_DOT1D_STP_PORT_STATE, SNMP_MAX_STP_PORTS
        )
        for oid, value in state_values.items():
            state = _to_int(value)
            port_states[_oid_index(oid)] = STP_PORT_STATES.get(state, str(state))
    except Exception:
        port_states = {}

    blocked_ports = [
        index_to_name.get(index, f'ifIndex {index}')
        for index, state in port_states.items()
        if state in STP_ALERT_STATES
    ]

    reasons = []
    if blocked_ports:
        reasons.append(
            'Portas em estado de bloqueio/loop: {}.'.format(', '.join(blocked_ports))
        )
    if (
        time_since_top_change is not None
        and time_since_top_change < STP_RECENT_CHANGE_HUNDREDTHS
    ):
        minutes = max(time_since_top_change, 0) / 6000
        reasons.append(
            'Mudança de topologia STP detectada há {:.1f} minuto(s).'.format(minutes)
        )

    has_alert = bool(blocked_ports) or (
        time_since_top_change is not None
        and time_since_top_change < STP_RECENT_CHANGE_HUNDREDTHS
    )
    reason = ' '.join(reasons) if reasons else 'STP estável, sem bloqueios ou mudanças recentes.'

    return {
        'has_alert': has_alert,
        'stp_changes': top_changes,
        'blocked_ports': blocked_ports,
        'reason': reason,
    }, port_states


async def _collect_snmp_async(ip, community):
    from pysnmp.hlapi.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
    )

    engine = SnmpEngine()
    target = UdpTransportTarget(
        (ip, 161),
        timeout=SNMP_TIMEOUT,
        retries=SNMP_RETRIES,
    )
    context = ContextData()

    for mp_model in (1, 0):
        auth = CommunityData(community, mpModel=mp_model)
        try:
            error_indication, error_status, _, var_binds = await getCmd(
                engine,
                auth,
                target,
                context,
                ObjectType(ObjectIdentity(OID_SYS_DESCR)),
                ObjectType(ObjectIdentity(OID_SYS_UPTIME)),
            )
            if error_indication:
                raise RuntimeError(str(error_indication))
            if error_status:
                raise RuntimeError(error_status.prettyPrint())
            break
        except Exception:
            if mp_model == 0:
                raise

    sys_descr = str(var_binds[0][1]) or None
    uptime_seconds = int(int(var_binds[1][1]) / 100)

    cpu_percent = None
    try:
        cpu_values = await _snmp_walk(
            engine, auth, target, context, OID_HR_PROCESSOR_LOAD, SNMP_MAX_PROCESSORS
        )
        loads = [load for load in (_to_int(v) for v in cpu_values.values()) if load is not None]
        if loads:
            cpu_percent = round(sum(loads) / len(loads), 1)
    except Exception:
        cpu_percent = None

    memory_percent = None
    try:
        storage_values = await _snmp_walk(
            engine, auth, target, context, OID_HR_STORAGE_TABLE, SNMP_MAX_STORAGE_ENTRIES
        )
        type_prefix = f'{OID_HR_STORAGE_TABLE}.2.'
        size_prefix = f'{OID_HR_STORAGE_TABLE}.5.'
        used_prefix = f'{OID_HR_STORAGE_TABLE}.6.'
        for oid, storage_type in storage_values.items():
            if not oid.startswith(type_prefix):
                continue
            if str(storage_type) != OID_HR_STORAGE_TYPE_RAM:
                continue
            index = oid[len(type_prefix):]
            size = _to_int(storage_values.get(f'{size_prefix}{index}'))
            used = _to_int(storage_values.get(f'{used_prefix}{index}'))
            if size and used is not None:
                memory_percent = round((used / size) * 100, 1)
            break
    except Exception:
        memory_percent = None

    descr_values = await _snmp_walk(
        engine, auth, target, context, OID_IF_DESCR, SNMP_MAX_INTERFACES
    )
    status_values = await _snmp_walk(
        engine, auth, target, context, OID_IF_OPER_STATUS, SNMP_MAX_INTERFACES
    )
    in_oid = OID_IF_HC_IN_OCTETS
    in_values = await _snmp_walk(
        engine, auth, target, context, in_oid, SNMP_MAX_INTERFACES
    )
    if not in_values:
        in_oid = OID_IF_IN_OCTETS
        in_values = await _snmp_walk(
            engine, auth, target, context, in_oid, SNMP_MAX_INTERFACES
        )
    out_oid = OID_IF_HC_OUT_OCTETS
    out_values = await _snmp_walk(
        engine, auth, target, context, out_oid, SNMP_MAX_INTERFACES
    )
    if not out_values:
        out_oid = OID_IF_OUT_OCTETS
        out_values = await _snmp_walk(
            engine, auth, target, context, out_oid, SNMP_MAX_INTERFACES
        )

    descr_items = list(descr_values.items())[:SNMP_MAX_INTERFACES]
    index_to_name = {
        _oid_index(oid): str(name)[:64] for oid, name in descr_items
    }

    vlans_summary, pvid_by_index = await _collect_vlans(
        engine, auth, target, context, index_to_name
    )
    loop_status, stp_states = await _collect_loop_status(
        engine, auth, target, context, index_to_name
    )

    interfaces = []
    for oid, name in descr_items:
        index = _oid_index(oid)
        status = status_values.get(f'{OID_IF_OPER_STATUS}.{index}')
        interfaces.append({
            'name': str(name)[:64],
            'status': 'UP' if status is not None and _to_int(status) == 1 else 'DOWN',
            'in_octets': _to_int(in_values.get(f'{in_oid}.{index}')),
            'out_octets': _to_int(out_values.get(f'{out_oid}.{index}')),
            'pvid': pvid_by_index.get(index),
            'stp_state': stp_states.get(index),
        })

    return {
        'sys_descr': sys_descr[:255] if sys_descr else None,
        'uptime_seconds': uptime_seconds,
        'cpu_percent': cpu_percent,
        'memory_percent': memory_percent,
        'interfaces_summary': interfaces,
        'vlans_summary': vlans_summary,
        'loop_status': loop_status,
    }


def collect_snmp(ip, community='public'):
    return asyncio.run(_collect_snmp_async(str(ip), community))


@system_job(interval=5)
class DeviceMonitorJob(JobRunner):
    class Meta:
        name = 'Device Monitoring'

    def run(self, *args, **kwargs):
        import icmplib

        devices = Device.objects.filter(
            primary_ip4__isnull=False
        ) | Device.objects.filter(
            primary_ip6__isnull=False
        )

        tagged = devices.filter(tags__name='monitorar').distinct()
        if tagged.exists():
            devices = tagged
        else:
            devices = devices.distinct()

        self.logger.info(f'Coletando métricas de {devices.count()} dispositivo(s)')

        for device in devices:
            ip = str(device.primary_ip.address).split('/')[0]
            try:
                host = icmplib.ping(str(ip), count=1, timeout=2, privileged=False)
                is_online = host.is_alive
                latency_ms = round(host.avg_rtt, 2) if is_online and host.avg_rtt is not None else None
            except Exception as exc:
                self.logger.warning(f'Falha ao pingar {device} ({ip}): {exc}')
                is_online = False
                latency_ms = None

            snmp_data = {}
            community = device.cf.get('snmp_community') or 'public'
            try:
                snmp_data = collect_snmp(ip, community) or {}
            except Exception as exc:
                self.logger.debug(f'Falha ao coletar SNMP de {device} ({ip}): {exc}')

            DeviceMetric.objects.create(
                device=device,
                is_online=is_online,
                latency_ms=latency_ms,
                sys_descr=snmp_data.get('sys_descr'),
                uptime_seconds=snmp_data.get('uptime_seconds'),
                cpu_percent=snmp_data.get('cpu_percent'),
                memory_percent=snmp_data.get('memory_percent'),
                interfaces_summary=snmp_data.get('interfaces_summary', []),
                vlans_summary=snmp_data.get('vlans_summary', []),
                loop_status=snmp_data.get('loop_status', {}),
            )
            status = 'ONLINE' if is_online else 'OFFLINE'
            self.logger.info(f'{device} ({ip}): {status} {latency_ms if latency_ms is not None else "-"} ms')
