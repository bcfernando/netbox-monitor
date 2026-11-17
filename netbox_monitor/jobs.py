import asyncio
import json
import logging
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta

from dcim.models import Device, Interface
from django.utils import timezone
from netbox.jobs import JobRunner, system_job

from .models import DeviceMetric, MonitorSettings

logger = logging.getLogger(__name__)

_CRITICAL_PORT_RE = re.compile(r'(?:sfp|ten|25g|40g)', re.IGNORECASE)

OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0'
OID_SYS_UPTIME = '1.3.6.1.2.1.1.3.0'
OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2'
OID_IF_OPER_STATUS = '1.3.6.1.2.1.2.2.1.8'
OID_IF_IN_OCTETS = '1.3.6.1.2.1.2.2.1.10'
OID_IF_OUT_OCTETS = '1.3.6.1.2.1.2.2.1.16'
OID_IF_HC_IN_OCTETS = '1.3.6.1.2.1.31.1.1.1.6'
OID_IF_HC_OUT_OCTETS = '1.3.6.1.2.1.31.1.1.1.10'
OID_IF_HIGH_SPEED = '1.3.6.1.2.1.31.1.1.1.15'
OID_IF_SPEED = '1.3.6.1.2.1.2.2.1.5'
OID_HR_PROCESSOR_LOAD = '1.3.6.1.2.1.25.3.3.1.2'
OID_CISCO_CPU_LOAD = '1.3.6.1.4.1.9.9.109.1.1.1.1.7'
OID_HPE_CPU_LOAD_1 = '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0'
OID_HPE_CPU_LOAD_2 = '1.3.6.1.4.1.25506.2.6.1.1.1.1.6'
OID_MIKROTIK_CPU_LOAD = '1.3.6.1.4.1.14988.1.1.3.10.0'
OID_HR_STORAGE_TABLE = '1.3.6.1.2.1.25.2.3.1'
OID_HR_STORAGE_TYPE_RAM = '1.3.6.1.2.1.25.2.1.2'
OID_ENT_PHY_SENSOR_TYPE = '1.3.6.1.2.1.99.1.1.1.1'
OID_ENT_PHY_SENSOR_SCALE = '1.3.6.1.2.1.99.1.1.1.2'
OID_ENT_PHY_SENSOR_PRECISION = '1.3.6.1.2.1.99.1.1.1.3'
OID_ENT_PHY_SENSOR_VALUE = '1.3.6.1.2.1.99.1.1.1.4'
OID_ENT_PHY_SENSOR_OPER_STATUS = '1.3.6.1.2.1.99.1.1.1.5'
OID_ENT_PHYSICAL_NAME = '1.3.6.1.2.1.47.1.1.1.1.7'
OID_MIKROTIK_TEMPERATURE = '1.3.6.1.4.1.14988.1.1.3.10.0'
OID_MIKROTIK_FAN_SPEED = '1.3.6.1.4.1.14988.1.1.3.11.0'
OID_CISCO_ENVMON_TEMPERATURE = '1.3.6.1.4.1.9.9.13.1.3'
OID_CISCO_ENVMON_FAN = '1.3.6.1.4.1.9.9.13.1.4'
OID_CISCO_ENVMON_TEMP_NAME = f'{OID_CISCO_ENVMON_TEMPERATURE}.1.1'
OID_CISCO_ENVMON_TEMP_VALUE = f'{OID_CISCO_ENVMON_TEMPERATURE}.1.2'
OID_CISCO_ENVMON_FAN_NAME = f'{OID_CISCO_ENVMON_FAN}.1.1'
OID_CISCO_ENVMON_FAN_STATE = f'{OID_CISCO_ENVMON_FAN}.1.2'
OID_PETH_MAIN_PSE_POWER = '1.3.6.1.2.1.105.1.3.1.1.2'
OID_PETH_MAIN_PSE_CONSUMPTION = '1.3.6.1.2.1.105.1.3.1.1.4'
OID_PETH_PSE_PORT_DETECTION_STATUS = '1.3.6.1.2.1.105.1.1.1.6'
OID_HPE_POE_PORT_ACTUAL_POWER = '1.3.6.1.4.1.11.2.14.11.1.9.1.1.1.3'
OID_DOT1D_BASE_PORT_IF_INDEX = '1.3.6.1.2.1.17.1.4.1.2'
OID_DOT1Q_VLAN_STATIC_NAME = '1.3.6.1.2.1.17.7.1.4.3.1.1'
OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS = '1.3.6.1.2.1.17.7.1.4.3.1.2'
OID_DOT1Q_VLAN_STATIC_UNTAGGED_PORTS = '1.3.6.1.2.1.17.7.1.4.3.1.4'
OID_DOT1Q_VLAN_CURRENT_EGRESS_PORTS = '1.3.6.1.2.1.17.7.1.4.2.1.4'
OID_DOT1Q_VLAN_CURRENT_UNTAGGED_PORTS = '1.3.6.1.2.1.17.7.1.4.2.1.5'
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

SNMP_TIMEOUT = 2
SNMP_RETRIES = 0
SNMP_TOTAL_TIMEOUT = 12
PING_TIMEOUT = 1
COLLECT_MAX_WORKERS = 10
SNMP_MAX_INTERFACES = 64
SNMP_MAX_PROCESSORS = 256
SNMP_MAX_STORAGE_ENTRIES = 2000
SNMP_MAX_VLANS = 512
SNMP_MAX_BRIDGE_PORTS = 4096
SNMP_MAX_STP_PORTS = 512
SNMP_MAX_SENSORS = 512
SNMP_MAX_POE_PORTS = 512
HARDWARE_COLLECTION_TIMEOUT = 4
POE_COLLECTION_TIMEOUT = 4

ENTITY_SENSOR_TYPE_CELSIUS = 8
ENTITY_SENSOR_TYPE_RPM = 10
ENTITY_SENSOR_OPER_STATUS = {
    1: 'OK',
    2: 'INDISPONÍVEL',
    3: 'FALHA',
}
CISCO_ENVMON_FAN_STATES = {
    1: 'OK',
    2: 'ALERTA',
    3: 'CRÍTICO',
    4: 'DESLIGADO',
    5: 'AUSENTE',
    6: 'FALHA',
}


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


def _decode_port_list(value):
    try:
        octets = list(value.asNumbers())
    except (AttributeError, TypeError, ValueError):
        if isinstance(value, (bytes, bytearray)):
            octets = list(value)
        else:
            try:
                octets = [int(part) for part in str(value).split()]
            except (TypeError, ValueError):
                return set()

    bridge_ports = set()
    for byte_index, octet in enumerate(octets):
        for bit in range(8):
            if octet & (0x80 >> bit):
                bridge_ports.add(byte_index * 8 + bit + 1)
    return bridge_ports


def _is_aruba_instant_on(sys_descr):
    text = (sys_descr or '').lower()
    return 'aruba' in text and ('instant on' in text or '1930' in text)


def _aruba_untagged_ports_are_tagged(egress_by_vid, untagged_by_vid):
    vlan1_untagged = untagged_by_vid.get(1, set())
    if not vlan1_untagged:
        return False
    for vlan_id, ports in egress_by_vid.items():
        if vlan_id == 1 or not ports:
            continue
        if not untagged_by_vid.get(vlan_id) and ports <= vlan1_untagged:
            return True
    return False


def _aruba_untagged_by_vid(egress_by_vid, untagged_by_vid):
    derived = {}
    for vlan_id, ports in egress_by_vid.items():
        reported = untagged_by_vid.get(vlan_id, set())
        derived[vlan_id] = ports - (reported & ports)

    others = set()
    for vlan_id, ports in derived.items():
        if vlan_id != 1:
            others |= ports
    derived[1] = untagged_by_vid.get(1, set()) - others
    return derived


async def _collect_vlans(engine, auth, target, context, index_to_name, sys_descr=None):
    async def _walk(base_oid, limit=SNMP_MAX_VLANS):
        try:
            return await _snmp_walk(engine, auth, target, context, base_oid, limit)
        except Exception:
            return {}

    base_port_values = await _walk(
        OID_DOT1D_BASE_PORT_IF_INDEX, SNMP_MAX_BRIDGE_PORTS
    )
    bridge_port_to_index = {}
    for oid, value in base_port_values.items():
        bridge_port = _to_int(_oid_index(oid))
        if_index = _to_int(value)
        if bridge_port is not None and if_index is not None:
            bridge_port_to_index[bridge_port] = str(if_index)

    def _if_index(bridge_port):
        return bridge_port_to_index.get(bridge_port, str(bridge_port))

    vlan_names = await _walk(OID_DOT1Q_VLAN_STATIC_NAME)
    egress_values = await _walk(OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS)
    untagged_values = await _walk(OID_DOT1Q_VLAN_STATIC_UNTAGGED_PORTS)
    if not egress_values:
        egress_values = await _walk(OID_DOT1Q_VLAN_CURRENT_EGRESS_PORTS)
    if not untagged_values:
        untagged_values = await _walk(OID_DOT1Q_VLAN_CURRENT_UNTAGGED_PORTS)

    egress_by_vid = {}
    for oid, value in egress_values.items():
        vlan_id = _to_int(_oid_index(oid))
        if vlan_id is not None:
            egress_by_vid[vlan_id] = _decode_port_list(value)

    untagged_by_vid = {}
    for oid, value in untagged_values.items():
        vlan_id = _to_int(_oid_index(oid))
        if vlan_id is not None:
            untagged_by_vid[vlan_id] = _decode_port_list(value)

    if _is_aruba_instant_on(sys_descr) and _aruba_untagged_ports_are_tagged(
        egress_by_vid, untagged_by_vid
    ):
        untagged_by_vid = _aruba_untagged_by_vid(egress_by_vid, untagged_by_vid)

    names = {}
    for oid, value in vlan_names.items():
        vlan_id = _to_int(_oid_index(oid))
        if vlan_id is not None:
            names[vlan_id] = str(value)[:64]

    pvid_by_index = {}
    for vlan_id in sorted(untagged_by_vid):
        for bridge_port in untagged_by_vid[vlan_id]:
            index = _if_index(bridge_port)
            if index in index_to_name and index not in pvid_by_index:
                pvid_by_index[index] = vlan_id

    pvid_values = await _walk(OID_DOT1Q_PVID)
    for oid, value in pvid_values.items():
        vlan_id = _to_int(value)
        bridge_port = _to_int(_oid_index(oid))
        if vlan_id is None or bridge_port is None:
            continue
        index = _if_index(bridge_port)
        if index in index_to_name and index not in pvid_by_index:
            pvid_by_index[index] = vlan_id

    tagged_by_index = {}
    for vlan_id in sorted(egress_by_vid):
        tagged_ports = egress_by_vid[vlan_id] - untagged_by_vid.get(vlan_id, set())
        for bridge_port in tagged_ports:
            index = _if_index(bridge_port)
            if index in index_to_name:
                tagged_by_index.setdefault(index, []).append(vlan_id)

    def _port_names(bridge_ports):
        names_found = {
            index_to_name[_if_index(bridge_port)]
            for bridge_port in bridge_ports
            if _if_index(bridge_port) in index_to_name
        }
        return sorted(names_found, key=str.lower)

    vlan_ids = set(names) | set(egress_by_vid) | set(untagged_by_vid)
    vlan_ids |= set(pvid_by_index.values())
    for vlans in tagged_by_index.values():
        vlan_ids |= set(vlans)

    vlans_summary = []
    for vlan_id in sorted(vlan_ids):
        untagged_ports = _port_names(untagged_by_vid.get(vlan_id, set()))
        tagged_ports = _port_names(
            egress_by_vid.get(vlan_id, set()) - untagged_by_vid.get(vlan_id, set())
        )
        vlans_summary.append({
            'vlan_id': vlan_id,
            'name': names.get(vlan_id) or f'VLAN {vlan_id}',
            'untagged_ports': untagged_ports,
            'tagged_ports': tagged_ports,
            'ports': sorted(
                set(untagged_ports) | set(tagged_ports), key=str.lower
            ),
        })
    return vlans_summary, pvid_by_index, tagged_by_index


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


def _entity_sensor_value(raw, scale, precision):
    try:
        raw = int(raw)
        scale = int(scale)
        precision = int(precision)
    except (TypeError, ValueError):
        return None
    return raw * (10.0 ** (scale - 9 - precision))


async def _collect_entity_sensors(engine, auth, target, context):
    names = {}
    try:
        name_values = await _snmp_walk(
            engine, auth, target, context, OID_ENT_PHYSICAL_NAME, SNMP_MAX_SENSORS
        )
        names = {
            _oid_index(oid): str(value)[:64] for oid, value in name_values.items()
        }
    except Exception:
        names = {}

    sensors = {}
    for column, oid in (
        ('type', OID_ENT_PHY_SENSOR_TYPE),
        ('scale', OID_ENT_PHY_SENSOR_SCALE),
        ('precision', OID_ENT_PHY_SENSOR_PRECISION),
        ('value', OID_ENT_PHY_SENSOR_VALUE),
        ('oper_status', OID_ENT_PHY_SENSOR_OPER_STATUS),
    ):
        try:
            values = await _snmp_walk(
                engine, auth, target, context, oid, SNMP_MAX_SENSORS
            )
        except Exception:
            values = {}
        for oid_key, value in values.items():
            sensors.setdefault(_oid_index(oid_key), {})[column] = value

    temperatures = []
    fans = []
    for index in sorted(sensors):
        entry = sensors[index]
        sensor_type = _to_int(entry.get('type'))
        raw = _to_int(entry.get('value'))
        if raw is None or sensor_type not in (
            ENTITY_SENSOR_TYPE_CELSIUS,
            ENTITY_SENSOR_TYPE_RPM,
        ):
            continue

        scale = _to_int(entry.get('scale'))
        precision = _to_int(entry.get('precision'))
        if scale is None:
            scale = 9
        if precision is None:
            precision = 0

        value = _entity_sensor_value(raw, scale, precision)
        if value is None:
            continue

        name = names.get(index) or f'Sensor {index}'
        status = ENTITY_SENSOR_OPER_STATUS.get(
            _to_int(entry.get('oper_status')), 'DESCONHECIDO'
        )

        if sensor_type == ENTITY_SENSOR_TYPE_CELSIUS:
            temperatures.append({'name': name, 'value_c': round(value, 1)})
        elif sensor_type == ENTITY_SENSOR_TYPE_RPM:
            fans.append({
                'name': name,
                'rpm': int(round(value)),
                'status': status,
            })

    return temperatures, fans


async def _collect_cisco_envmon(engine, auth, target, context):
    temperatures = []
    fans = []

    try:
        temp_names = await _snmp_walk(
            engine, auth, target, context, OID_CISCO_ENVMON_TEMP_NAME, SNMP_MAX_SENSORS
        )
        temp_values = await _snmp_walk(
            engine, auth, target, context, OID_CISCO_ENVMON_TEMP_VALUE, SNMP_MAX_SENSORS
        )
        names = {
            _oid_index(oid): str(value)[:64] for oid, value in temp_names.items()
        }
        for oid, value in temp_values.items():
            index = _oid_index(oid)
            temperature = _to_int(value)
            if temperature is None:
                continue
            temperatures.append({
                'name': names.get(index) or f'Sensor {index}',
                'value_c': temperature,
            })
    except Exception:
        temperatures = []

    try:
        fan_names = await _snmp_walk(
            engine, auth, target, context, OID_CISCO_ENVMON_FAN_NAME, SNMP_MAX_SENSORS
        )
        fan_states = await _snmp_walk(
            engine, auth, target, context, OID_CISCO_ENVMON_FAN_STATE, SNMP_MAX_SENSORS
        )
        names = {
            _oid_index(oid): str(value)[:64] for oid, value in fan_names.items()
        }
        for oid, value in fan_states.items():
            index = _oid_index(oid)
            state = _to_int(value)
            fans.append({
                'name': names.get(index) or f'Ventoinha {index}',
                'rpm': None,
                'status': CISCO_ENVMON_FAN_STATES.get(state, str(state)),
            })
    except Exception:
        fans = []

    return temperatures, fans


async def _collect_mikrotik_hardware(engine, auth, target, context):
    temperature = None
    fan = None

    try:
        value = await _snmp_get(
            engine, auth, target, context, OID_MIKROTIK_TEMPERATURE
        )
        raw = _to_int(value)
        if raw is not None:
            temperature = {'name': 'Temperatura', 'value_c': raw}
    except Exception:
        temperature = None

    try:
        value = await _snmp_get(
            engine, auth, target, context, OID_MIKROTIK_FAN_SPEED
        )
        raw = _to_int(value)
        if raw is not None:
            fan = {'name': 'Ventoinha', 'rpm': raw, 'status': 'OK'}
    except Exception:
        fan = None

    return temperature, fan


async def _collect_hardware_metrics(engine, auth, target, context):
    temperatures, fans = await _collect_entity_sensors(
        engine, auth, target, context
    )

    if not temperatures or not fans:
        cisco_temperatures, cisco_fans = await _collect_cisco_envmon(
            engine, auth, target, context
        )
        if not temperatures:
            temperatures = cisco_temperatures
        if not fans:
            fans = cisco_fans

    if not temperatures or not fans:
        mikrotik_temperature, mikrotik_fan = await _collect_mikrotik_hardware(
            engine, auth, target, context
        )
        if not temperatures and mikrotik_temperature is not None:
            temperatures = [mikrotik_temperature]
        if not fans and mikrotik_fan is not None:
            fans = [mikrotik_fan]

    return {'temperatures': temperatures, 'fans': fans}


async def _collect_poe(engine, auth, target, context):
    budget_watts = None
    used_watts = None

    try:
        value = await _snmp_get(
            engine, auth, target, context, f'{OID_PETH_MAIN_PSE_POWER}.1'
        )
        budget_watts = _to_int(value)
    except Exception:
        budget_watts = None

    if budget_watts is None:
        try:
            budget_values = await _snmp_walk(
                engine, auth, target, context,
                OID_PETH_MAIN_PSE_POWER, SNMP_MAX_POE_PORTS,
            )
            totals = [
                total for total in (_to_int(v) for v in budget_values.values())
                if total is not None
            ]
            if totals:
                budget_watts = sum(totals)
        except Exception:
            budget_watts = None

    try:
        value = await _snmp_get(
            engine, auth, target, context, f'{OID_PETH_MAIN_PSE_CONSUMPTION}.1'
        )
        used_watts = _to_int(value)
    except Exception:
        used_watts = None

    if used_watts is None:
        try:
            used_values = await _snmp_walk(
                engine, auth, target, context,
                OID_PETH_MAIN_PSE_CONSUMPTION, SNMP_MAX_POE_PORTS,
            )
            totals = [
                total for total in (_to_int(v) for v in used_values.values())
                if total is not None
            ]
            if totals:
                used_watts = sum(totals)
        except Exception:
            used_watts = None

    status_values = {}
    try:
        status_values = await _snmp_walk(
            engine, auth, target, context,
            OID_PETH_PSE_PORT_DETECTION_STATUS, SNMP_MAX_POE_PORTS,
        )
    except Exception:
        status_values = {}

    watts_values = {}
    try:
        watts_values = await _snmp_walk(
            engine, auth, target, context,
            OID_HPE_POE_PORT_ACTUAL_POWER, SNMP_MAX_POE_PORTS,
        )
    except Exception:
        watts_values = {}

    ports = {}
    port_watts_total = 0.0
    has_port_watts = False
    watts_by_index = {
        _oid_index(oid): _to_int(value)
        for oid, value in watts_values.items()
    }
    for oid, value in status_values.items():
        index = _oid_index(oid)
        detected = _to_int(value)
        raw_watts = watts_by_index.get(index)
        watts = round(raw_watts / 1000, 1) if raw_watts is not None else None
        if watts is not None:
            port_watts_total += watts
            has_port_watts = True
        active = detected == 3
        if active or (watts is not None and watts > 0):
            ports[index] = {'active': active, 'watts': watts}

    for index, raw_watts in watts_by_index.items():
        if index in ports:
            continue
        if raw_watts is None:
            continue
        watts = round(raw_watts / 1000, 1)
        if watts > 0:
            ports[index] = {'active': False, 'watts': watts}
            port_watts_total += watts
            has_port_watts = True

    if used_watts is None and has_port_watts:
        used_watts = int(round(port_watts_total))

    has_active_ports = any(port.get('active') for port in ports.values())
    if budget_watts is None and used_watts is None and not has_active_ports:
        return None

    return {
        'budget_watts': budget_watts,
        'used_watts': used_watts,
        'ports': ports,
    }


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

    if cpu_percent is None:
        try:
            cisco_values = await _snmp_walk(
                engine, auth, target, context, OID_CISCO_CPU_LOAD, SNMP_MAX_PROCESSORS
            )
            loads = [
                load for load in (_to_int(v) for v in cisco_values.values())
                if load is not None
            ]
            if loads:
                cpu_percent = round(sum(loads) / len(loads), 1)
        except Exception:
            cpu_percent = None

    if cpu_percent is None:
        for oid in (
            OID_HPE_CPU_LOAD_1,
            OID_HPE_CPU_LOAD_2,
            OID_MIKROTIK_CPU_LOAD,
        ):
            try:
                value = await _snmp_get(engine, auth, target, context, oid)
                load = _to_int(value)
                if load is not None:
                    cpu_percent = float(load)
                    break
            except Exception:
                continue

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

    speed_oid = OID_IF_HIGH_SPEED
    speed_values = await _snmp_walk(
        engine, auth, target, context, speed_oid, SNMP_MAX_INTERFACES
    )
    if not speed_values:
        speed_oid = OID_IF_SPEED
        speed_values = await _snmp_walk(
            engine, auth, target, context, speed_oid, SNMP_MAX_INTERFACES
        )

    descr_items = list(descr_values.items())[:SNMP_MAX_INTERFACES]
    index_to_name = {
        _oid_index(oid): str(name)[:64] for oid, name in descr_items
    }

    vlans_summary, pvid_by_index, tagged_by_index = await _collect_vlans(
        engine, auth, target, context, index_to_name, sys_descr
    )
    loop_status, stp_states = await _collect_loop_status(
        engine, auth, target, context, index_to_name
    )

    interfaces = []
    for oid, name in descr_items:
        index = _oid_index(oid)
        status = status_values.get(f'{OID_IF_OPER_STATUS}.{index}')
        speed_mbps = None
        speed_raw = _to_int(speed_values.get(f'{speed_oid}.{index}'))
        if speed_raw is not None and speed_raw > 0:
            if speed_oid == OID_IF_HIGH_SPEED:
                speed_mbps = speed_raw
            else:
                speed_mbps = round(speed_raw / 1_000_000)
        interfaces.append({
            'name': str(name)[:64],
            'status': 'UP' if status is not None and _to_int(status) == 1 else 'DOWN',
            'speed_mbps': speed_mbps,
            'in_octets': _to_int(in_values.get(f'{in_oid}.{index}')),
            'out_octets': _to_int(out_values.get(f'{out_oid}.{index}')),
            'pvid': pvid_by_index.get(index),
            'tagged_vlans': sorted(tagged_by_index.get(index, [])),
            'stp_state': stp_states.get(index),
        })

    hardware_metrics = {'temperatures': [], 'fans': []}
    try:
        hardware_metrics = await asyncio.wait_for(
            _collect_hardware_metrics(engine, auth, target, context),
            timeout=HARDWARE_COLLECTION_TIMEOUT,
        )
    except Exception:
        hardware_metrics = {'temperatures': [], 'fans': []}

    try:
        poe = await asyncio.wait_for(
            _collect_poe(engine, auth, target, context),
            timeout=POE_COLLECTION_TIMEOUT,
        )
    except Exception:
        poe = None
    if poe:
        hardware_metrics['poe'] = poe

    return {
        'sys_descr': sys_descr[:255] if sys_descr else None,
        'uptime_seconds': uptime_seconds,
        'cpu_percent': cpu_percent,
        'memory_percent': memory_percent,
        'interfaces_summary': interfaces,
        'vlans_summary': vlans_summary,
        'loop_status': loop_status,
        'hardware_metrics': hardware_metrics,
    }


def collect_snmp(ip, community='public'):
    async def _run():
        return await asyncio.wait_for(
            _collect_snmp_async(str(ip), community),
            timeout=SNMP_TOTAL_TIMEOUT,
        )

    return asyncio.run(_run())


def collect_device(ip, community='public'):
    """Coleta ping + SNMP de um dispositivo. Não acessa o banco de dados."""
    import icmplib

    data = {
        'is_online': False,
        'latency_ms': None,
        'ping_error': None,
        'snmp_error': None,
    }

    try:
        host = icmplib.ping(str(ip), count=1, timeout=PING_TIMEOUT, privileged=False)
        data['is_online'] = host.is_alive
        if host.is_alive and host.avg_rtt is not None:
            data['latency_ms'] = round(host.avg_rtt, 2)
    except Exception as exc:
        data['ping_error'] = str(exc)

    if data['is_online']:
        try:
            snmp_data = collect_snmp(ip, community) or {}
            data.update({
                'sys_descr': snmp_data.get('sys_descr'),
                'uptime_seconds': snmp_data.get('uptime_seconds'),
                'cpu_percent': snmp_data.get('cpu_percent'),
                'memory_percent': snmp_data.get('memory_percent'),
                'interfaces_summary': snmp_data.get('interfaces_summary', []),
                'vlans_summary': snmp_data.get('vlans_summary', []),
                'loop_status': snmp_data.get('loop_status', {}),
                'hardware_metrics': snmp_data.get('hardware_metrics', {}),
            })
        except Exception as exc:
            data['snmp_error'] = str(exc)

    return data


def send_webhook_alert(message):
    settings_obj = MonitorSettings.get_solo()
    if not settings_obj.enabled:
        logger.info('Alertas desativados; webhook não enviado.')
        return False

    webhook_url = (settings_obj.webhook_url or '').strip()
    if not webhook_url:
        return False

    if 'api.telegram.org' in webhook_url:
        payload = {
            'chat_id': settings_obj.telegram_chat_id,
            'text': message,
            'parse_mode': 'HTML',
        }
    else:
        payload = {'content': message, 'text': message}

    try:
        request = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            response.read()
    except Exception as exc:
        logger.warning(f'Falha ao enviar alerta para o webhook: {exc}')
        return False
    return True


def _device_ip(device):
    if device.primary_ip is None:
        return '-'
    return str(device.primary_ip.address).split('/')[0]


def _uplink_interface_names(device):
    names = set()
    interfaces = Interface.objects.filter(device=device).prefetch_related('tags')
    for interface in interfaces:
        haystack = ' '.join(
            filter(
                None,
                (
                    interface.description or '',
                    getattr(interface, 'label', '') or '',
                ),
            )
        ).lower()
        tagged = any(
            'uplink' in (tag.name or '').lower() for tag in interface.tags.all()
        )
        if 'uplink' in haystack or tagged:
            name = (interface.name or '').strip().lower()
            if name:
                names.add(name)
    return names


def _is_critical_port(name, uplink_names):
    name = (name or '').strip()
    if name.lower() in uplink_names:
        return True
    if _CRITICAL_PORT_RE.search(name):
        return True
    numbers = re.findall(r'\d+', name)
    return bool(numbers and int(numbers[-1]) > 48)


def _port_status_map(interfaces_summary):
    return {
        (interface.get('name') or '').strip(): (interface.get('status') or 'DOWN').upper()
        for interface in interfaces_summary or []
        if (interface.get('name') or '').strip()
    }


def _critical_port_alerts(device, previous, data):
    current_summary = data.get('interfaces_summary') or []
    previous_summary = previous.interfaces_summary or []
    if not data.get('is_online') or not current_summary or not previous_summary:
        return []

    current_ports = _port_status_map(current_summary)
    previous_ports = _port_status_map(previous_summary)
    uplink_names = _uplink_interface_names(device)

    alerts = []
    for name, previous_status in previous_ports.items():
        if not _is_critical_port(name, uplink_names):
            continue
        current_status = current_ports.get(name)
        if current_status is None:
            continue
        if previous_status == 'UP' and current_status == 'DOWN':
            alerts.append(
                f'⚠️ <b>UPLINK / PORTA CRÍTICA DOWN</b>\n'
                f'Switch: {device.name}\n'
                f'Porta: {name}\n'
                f'IP: {_device_ip(device)}'
            )
        elif previous_status == 'DOWN' and current_status == 'UP':
            alerts.append(
                f'✅ <b>UPLINK RESTAURADO</b>\n'
                f'Switch: {device.name}\n'
                f'Porta: {name}\n'
                f'IP: {_device_ip(device)}'
            )
    return alerts


def check_metric_alerts(device, data):
    previous = DeviceMetric.objects.filter(device=device).order_by('-timestamp').first()
    if previous is None:
        return

    settings_obj = MonitorSettings.get_solo()
    alerts = []
    if previous.is_online and not data.get('is_online'):
        alerts.append(
            f'🔴 <b>OFFLINE</b>\n'
            f'Dispositivo: {device.name}\n'
            f'IP: {_device_ip(device)}'
        )
    elif not previous.is_online and data.get('is_online'):
        alerts.append(
            f'🟢 <b>ONLINE (Recuperado)</b>\n'
            f'Dispositivo: {device.name}\n'
            f'IP: {_device_ip(device)}'
        )

    threshold = settings_obj.latency_threshold_ms or 0
    latency_ms = data.get('latency_ms')
    if (
        threshold > 0
        and data.get('is_online')
        and latency_ms is not None
        and latency_ms > threshold
        and (
            not previous.is_online
            or (
                previous.latency_ms is not None
                and previous.latency_ms <= threshold
            )
        )
    ):
        alerts.append(
            f'🟠 <b>LATÊNCIA ALTA</b>\n'
            f'Dispositivo: {device.name}\n'
            f'IP: {_device_ip(device)}\n'
            f'Latência atual: {float(latency_ms):.2f} ms\n'
            f'Limite configurado: {threshold} ms'
        )

    was_loop_alert = bool((previous.loop_status or {}).get('has_alert'))
    loop_status = data.get('loop_status') or {}
    if not was_loop_alert and loop_status.get('has_alert'):
        reason = loop_status.get('reason') or 'Motivo não informado.'
        alerts.append(
            f'⚠️ <b>LOOP DE REDE / STP DETECTADO</b>\n'
            f'Dispositivo: {device.name}\n'
            f'IP: {_device_ip(device)}\n'
            f'Motivo: {reason}'
        )

    if settings_obj.alert_on_uplink_down:
        alerts.extend(_critical_port_alerts(device, previous, data))

    for message in alerts:
        send_webhook_alert(message)


def cleanup_old_metrics():
    retention_days = MonitorSettings.get_solo().retention_days
    try:
        retention_days = int(retention_days)
    except (TypeError, ValueError):
        retention_days = 30

    if retention_days <= 0:
        return 0

    cutoff = timezone.now() - timedelta(days=retention_days)
    deleted, _ = DeviceMetric.objects.filter(timestamp__lt=cutoff).delete()
    return deleted


def save_metric(device, data):
    return DeviceMetric.objects.create(
        device=device,
        is_online=data.get('is_online', False),
        latency_ms=data.get('latency_ms'),
        sys_descr=data.get('sys_descr'),
        uptime_seconds=data.get('uptime_seconds'),
        cpu_percent=data.get('cpu_percent'),
        memory_percent=data.get('memory_percent'),
        interfaces_summary=data.get('interfaces_summary', []),
        vlans_summary=data.get('vlans_summary', []),
        loop_status=data.get('loop_status', {}),
        hardware_metrics=data.get('hardware_metrics', {}),
    )


@system_job(interval=1)
class DeviceMonitorJob(JobRunner):
    class Meta:
        name = 'Device Monitoring'

    def run(self, *args, **kwargs):
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

        targets = []
        for device in devices:
            ip = str(device.primary_ip.address).split('/')[0]
            community = device.cf.get('snmp_community') or 'public'
            targets.append((device, ip, community))

        self.logger.info(
            f'Coletando métricas de {len(targets)} dispositivo(s) em paralelo '
            f'(até {COLLECT_MAX_WORKERS} simultâneos)'
        )

        results = {}
        if targets:
            with ThreadPoolExecutor(max_workers=COLLECT_MAX_WORKERS) as executor:
                futures = {
                    executor.submit(collect_device, ip, community): device
                    for device, ip, community in targets
                }
                for future in as_completed(futures):
                    device = futures[future]
                    try:
                        results[device.pk] = future.result()
                    except Exception as exc:
                        self.logger.warning(f'Falha ao coletar {device}: {exc}')

        for device, ip, community in targets:
            data = results.get(device.pk)
            if data is None:
                continue
            if data.get('ping_error'):
                self.logger.warning(
                    f'Falha ao pingar {device} ({ip}): {data["ping_error"]}'
                )
            if data.get('snmp_error'):
                self.logger.debug(
                    f'Falha ao coletar SNMP de {device} ({ip}): {data["snmp_error"]}'
                )
            check_metric_alerts(device, data)
            save_metric(device, data)
            status = 'ONLINE' if data.get('is_online') else 'OFFLINE'
            latency_ms = data.get('latency_ms')
            self.logger.info(
                f'{device} ({ip}): {status} '
                f'{latency_ms if latency_ms is not None else "-"} ms'
            )

        deleted = cleanup_old_metrics()
        self.logger.info(f'Limpeza de histórico: {deleted} registro(s) removido(s)')
