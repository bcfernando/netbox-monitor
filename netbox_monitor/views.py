import csv
import re
from datetime import timedelta

from django.apps import apps
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views import View

from dcim.models import CableTermination, Device, Interface
from ipam.models import VLAN
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from .forms import MonitorSettingsForm
from .jobs import DeviceMonitorJob, collect_device, save_metric, send_webhook_alert
from .models import DeviceMetric, MonitorSettings

_VIRTUAL_INTERFACE_RE = re.compile(
    r'(?:^|[^a-z])(?:loopback|lo|vlan|null|mgmt|trk|port-channel)\d*(?:[^a-z]|$)',
    re.IGNORECASE,
)
_SFP_INTERFACE_RE = re.compile(
    r'(?:sfp|ten|xfi|forty|hundred|25g|40g|100g)',
    re.IGNORECASE,
)
_FACEPLATE_GROUP_SIZE = 6

_SYNC_SFP_INTERFACE_RE = re.compile(
    r'(?:sfp|ten|25g|40g)',
    re.IGNORECASE,
)

_VENDOR_THEMES = (
    ('aruba', ('aruba', 'instant on')),
    ('hpe', ('hpe', 'hewlett', 'hp')),
    ('cisco', ('cisco', 'catalyst')),
    ('mikrotik', ('mikrotik', 'routeros')),
    ('ubiquiti', ('ubiquiti', 'unifi', 'edgeswitch')),
)

_VENDOR_LABELS = {
    'aruba': 'Aruba',
    'hpe': 'HPE',
    'cisco': 'Cisco',
    'mikrotik': 'MikroTik',
    'ubiquiti': 'Ubiquiti',
    'default': 'Switch',
}

_VENDOR_CONSOLE_THEMES = {'aruba', 'hpe', 'cisco'}

_RANGE_OPTIONS = (
    ('1h', timedelta(hours=1), 'última 1 hora'),
    ('6h', timedelta(hours=6), 'últimas 6 horas'),
    ('24h', timedelta(hours=24), 'últimas 24 horas'),
    ('7d', timedelta(days=7), 'últimos 7 dias'),
    ('30d', timedelta(days=30), 'últimos 30 dias'),
)
_RANGE_MAP = {key: (delta, label) for key, delta, label in _RANGE_OPTIONS}
_DEFAULT_RANGE = '1h'
_MAX_CHART_POINTS = 60
_INCIDENT_WINDOW = timedelta(hours=24)
_INCIDENT_LIMIT = 10
_SLA_WINDOW = timedelta(days=7)


def _bandwidth_mbps(previous, current, interval):
    try:
        previous = int(previous)
        current = int(current)
    except (TypeError, ValueError):
        return None
    delta = current - previous
    if delta < 0:
        return None
    return round((delta * 8) / interval / 1_000_000, 3)


def _interfaces_with_rates(latest, previous):
    if latest is None:
        return []

    interval = None
    previous_by_name = {}
    if previous is not None:
        interval = (latest.timestamp - previous.timestamp).total_seconds()
        if interval <= 0:
            interval = None
        else:
            for interface in previous.interfaces_summary or []:
                previous_by_name[interface.get('name')] = interface

    rows = []
    for interface in latest.interfaces_summary or []:
        row = dict(interface)
        row['download_mbps'] = None
        row['upload_mbps'] = None
        row['speed_display'] = _format_speed(interface.get('speed_mbps'))
        try:
            row['speed_is_fast'] = float(interface.get('speed_mbps')) >= 1000
        except (TypeError, ValueError):
            row['speed_is_fast'] = False
        if interval:
            prev = previous_by_name.get(interface.get('name'))
            if prev:
                row['download_mbps'] = _bandwidth_mbps(
                    prev.get('in_octets'), interface.get('in_octets'), interval
                )
                row['upload_mbps'] = _bandwidth_mbps(
                    prev.get('out_octets'), interface.get('out_octets'), interval
                )
        rows.append(row)
    return rows


def _aggregate_traffic(interface_rows):
    total = 0.0
    has_value = False
    for row in interface_rows or []:
        download = row.get('download_mbps')
        upload = row.get('upload_mbps')
        if download is not None:
            total += float(download)
            has_value = True
        if upload is not None:
            total += float(upload)
            has_value = True
    if not has_value:
        return None
    return round(total, 3)


def _traffic_series(metrics):
    values = []
    previous = None
    for metric in metrics:
        if previous is None:
            values.append(None)
        else:
            values.append(_aggregate_traffic(_interfaces_with_rates(metric, previous)))
        previous = metric
    return values


def _format_uptime(metric):
    if metric is None or metric.uptime_seconds is None:
        return '-'
    return metric.uptime_display or '-'


def _loop_flag(metric):
    if metric is None or not isinstance(metric.loop_status, dict):
        return None
    return bool(metric.loop_status.get('has_alert'))


def _build_recent_incidents(devices, since, limit=_INCIDENT_LIMIT):
    metrics = (
        DeviceMetric.objects.filter(device__in=devices)
        .select_related('device')
        .order_by('device_id', 'timestamp')
    )

    prior = {
        metric.device_id: metric
        for metric in metrics.filter(timestamp__lt=since)
        .order_by('device_id', '-timestamp')
        .distinct('device_id')
    }

    events = []
    current_device = None
    previous = None

    for metric in metrics.filter(timestamp__gte=since):
        if metric.device_id != current_device:
            current_device = metric.device_id
            previous = prior.get(metric.device_id)

        if previous is not None:
            was_online = bool(previous.is_online)
            is_online = bool(metric.is_online)

            if was_online and not is_online:
                events.append({
                    'device': metric.device,
                    'timestamp': metric.timestamp,
                    'event_type': 'OFFLINE',
                    'badge_class': 'text-bg-danger',
                    'description': 'Equipamento ficou offline (ONLINE → OFFLINE).',
                })
            elif not was_online and is_online:
                events.append({
                    'device': metric.device,
                    'timestamp': metric.timestamp,
                    'event_type': 'ONLINE',
                    'badge_class': 'text-bg-success',
                    'description': 'Conectividade restabelecida (OFFLINE → ONLINE).',
                })

            if _loop_flag(metric) and not _loop_flag(previous):
                loop_status = metric.loop_status or {}
                events.append({
                    'device': metric.device,
                    'timestamp': metric.timestamp,
                    'event_type': 'LOOP / STP',
                    'badge_class': 'text-bg-warning',
                    'description': loop_status.get('reason')
                    or 'Possível loop de rede / alteração STP detectada.',
                })

        previous = metric

    events.sort(key=lambda event: event['timestamp'], reverse=True)
    return events[:limit]


def _downsample(items, limit=_MAX_CHART_POINTS):
    total = len(items)
    if total <= limit:
        return items
    step = (total - 1) / (limit - 1)
    indices = sorted({round(index * step) for index in range(limit)})
    return [items[index] for index in indices]


def _port_history_series(metrics):
    names = set()
    for metric in metrics:
        for interface in metric.interfaces_summary or []:
            name = (interface.get('name') or '').strip()
            if name:
                names.add(name)

    ordered = sorted(names, key=_natural_sort_key)
    ports = {
        name: {'download': [None] * len(metrics), 'upload': [None] * len(metrics)}
        for name in ordered
    }

    previous = None
    for index, metric in enumerate(metrics):
        if previous is not None:
            interval = (metric.timestamp - previous.timestamp).total_seconds()
            if interval > 0:
                previous_by_name = {
                    (item.get('name') or '').strip(): item
                    for item in previous.interfaces_summary or []
                }
                for interface in metric.interfaces_summary or []:
                    name = (interface.get('name') or '').strip()
                    entry = ports.get(name)
                    prev = previous_by_name.get(name)
                    if entry is None or prev is None:
                        continue
                    entry['download'][index] = _bandwidth_mbps(
                        prev.get('in_octets'), interface.get('in_octets'), interval
                    )
                    entry['upload'][index] = _bandwidth_mbps(
                        prev.get('out_octets'), interface.get('out_octets'), interval
                    )
        previous = metric

    return {
        'labels': [m.timestamp.strftime('%d/%m %H:%M:%S') for m in metrics],
        'ports': ports,
    }


def _physical_interface_rows(interface_rows):
    return [
        row for row in interface_rows
        if not _VIRTUAL_INTERFACE_RE.search(row.get('name') or '')
    ]


def _natural_sort_key(value):
    return [
        int(part) if part.isdigit() else part.lower()
        for part in re.split(r'(\d+)', value or '')
    ]


def _port_number(name, fallback):
    matches = re.findall(r'(\d+)', name or '')
    if matches:
        return str(int(matches[-1]))
    return str(fallback)


def _sync_interface_type(port_name):
    name = (port_name or '').strip()
    if _SYNC_SFP_INTERFACE_RE.search(name):
        return '10gbase-x-sfpp'
    numbers = re.findall(r'\d+', name)
    if numbers and int(numbers[-1]) > 48:
        return '10gbase-x-sfpp'
    return '1000base-t'


def _format_rate(value):
    if value is None:
        return '—'
    return f'{float(value):.2f} Mbps'


def _format_speed(speed_mbps):
    if speed_mbps is None:
        return None
    try:
        speed = float(speed_mbps)
    except (TypeError, ValueError):
        return None
    if speed <= 0:
        return None
    if speed >= 1000:
        gbps = speed / 1000
        if gbps == int(gbps):
            return f'{int(gbps)} Gbps'
        return f'{gbps:.1f} Gbps'
    if speed == int(speed):
        return f'{int(speed)} Mbps'
    return f'{speed:.1f} Mbps'


def _temperature_badge_class(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 'text-bg-secondary'
    if value >= 70:
        return 'text-bg-danger'
    if value >= 55:
        return 'text-bg-warning'
    return 'text-bg-success'


def _fan_badge_class(status):
    return 'text-bg-success' if status == 'OK' else 'text-bg-warning'


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _poe_summary(hardware_metrics):
    if not isinstance(hardware_metrics, dict):
        return None
    poe = hardware_metrics.get('poe')
    if not isinstance(poe, dict):
        return None

    budget_watts = _to_float(poe.get('budget_watts'))
    used_watts = _to_float(poe.get('used_watts'))
    ports = poe.get('ports') if isinstance(poe.get('ports'), dict) else {}
    active_ports = sum(
        1 for entry in ports.values()
        if isinstance(entry, dict) and entry.get('active')
    )

    if budget_watts is None and used_watts is None and not active_ports:
        return None

    percent = None
    if used_watts is not None and budget_watts is not None and budget_watts > 0:
        percent = round(min(max(used_watts / budget_watts * 100, 0), 100), 1)

    if percent is None:
        badge_class = 'text-bg-secondary'
        bar_class = 'bg-secondary'
    elif percent >= 85:
        badge_class = 'text-bg-danger'
        bar_class = 'bg-danger'
    elif percent >= 60:
        badge_class = 'text-bg-warning'
        bar_class = 'bg-warning'
    else:
        badge_class = 'text-bg-success'
        bar_class = 'bg-success'

    if budget_watts is not None and budget_watts.is_integer():
        budget_watts = int(budget_watts)
    if used_watts is not None and used_watts.is_integer():
        used_watts = int(used_watts)

    return {
        'budget_watts': budget_watts,
        'used_watts': used_watts,
        'percent': percent,
        'badge_class': badge_class,
        'bar_class': bar_class,
        'active_ports': active_ports,
    }


def _annotate_poe(interface_rows, hardware_metrics):
    if not isinstance(hardware_metrics, dict):
        return interface_rows
    poe = hardware_metrics.get('poe')
    if not isinstance(poe, dict):
        return interface_rows
    ports = poe.get('ports')
    if not isinstance(ports, dict):
        return interface_rows

    normalized = {}
    for key, entry in ports.items():
        if isinstance(entry, dict):
            normalized[str(key).strip()] = entry

    for row in interface_rows:
        name = (row.get('name') or '').strip()
        status = (row.get('status') or 'DOWN').upper()
        port_number = _port_number(name, '')
        entry = normalized.get(port_number)
        is_poe = bool(
            entry
            and entry.get('active')
            and name.isdigit()
            and status == 'UP'
        )
        row['is_poe'] = is_poe
        row['poe_active'] = is_poe
        row['poe_watts'] = entry.get('watts') if is_poe else None
    return interface_rows


def _annotate_neighbors(interface_rows, hardware_metrics):
    if not isinstance(hardware_metrics, dict):
        return interface_rows
    neighbors = hardware_metrics.get('neighbors')
    if not isinstance(neighbors, list):
        return interface_rows

    by_port = {}
    for item in neighbors:
        if not isinstance(item, dict):
            continue
        port = str(item.get('local_port') or '').strip().lower()
        if not port:
            continue
        by_port.setdefault(port, item)
        normalized = re.sub(r'[^a-z0-9]', '', port)
        if normalized:
            by_port.setdefault(normalized, item)

    for row in interface_rows:
        name = (row.get('name') or '').strip().lower()
        neighbor = by_port.get(name)
        if neighbor is None:
            neighbor = by_port.get(re.sub(r'[^a-z0-9]', '', name))
        row['neighbor_device'] = (
            neighbor.get('remote_device') if neighbor else None
        )
        row['neighbor_port'] = neighbor.get('remote_port') if neighbor else None
        row['neighbor_protocol'] = neighbor.get('protocol') if neighbor else None
    return interface_rows


def _port_tooltip(interface):
    pvid = interface.get('pvid')
    is_up = (interface.get('status') or 'DOWN').upper() == 'UP'
    speed = _format_speed(interface.get('speed_mbps')) if is_up else None
    tooltip = (
        '{} | {} | Velocidade: {} | VLAN (PVID): {} | STP: {} | '
        'Download: {} | Upload: {}'
    ).format(
        interface.get('name') or '—',
        interface.get('status') or 'DOWN',
        speed or '—',
        pvid if pvid is not None else '—',
        interface.get('stp_state') or '—',
        _format_rate(interface.get('download_mbps')),
        _format_rate(interface.get('upload_mbps')),
    )
    if interface.get('poe_active'):
        watts = interface.get('poe_watts')
        tooltip += ' | PoE: ⚡' + (f' {watts}W' if watts is not None else '')
    if interface.get('neighbor_device'):
        protocol = interface.get('neighbor_protocol') or 'LLDP'
        remote_port = interface.get('neighbor_port') or '—'
        tooltip += (
            f' | Vizinho ({protocol}): {interface["neighbor_device"]}'
            f' [{remote_port}]'
        )
    tagged_vlans = interface.get('tagged_vlans') or []
    if tagged_vlans:
        tooltip += ' | VLANs Tagged: ' + ', '.join(str(vlan) for vlan in tagged_vlans)
    return tooltip


def _faceplate_port(interface, number):
    status = (interface.get('status') or 'DOWN').upper()
    stp_state = (interface.get('stp_state') or '').upper()
    return {
        'name': interface.get('name') or '',
        'status': status,
        'is_up': status == 'UP',
        'number': number,
        'pvid': interface.get('pvid'),
        'tagged_vlans': interface.get('tagged_vlans') or [],
        'stp_state': stp_state,
        'is_loop': stp_state in ('BLOCKING', 'BROKEN'),
        'speed_display': interface.get('speed_display'),
        'download_mbps': interface.get('download_mbps'),
        'upload_mbps': interface.get('upload_mbps'),
        'neighbor_device': interface.get('neighbor_device'),
        'neighbor_port': interface.get('neighbor_port'),
        'neighbor_protocol': interface.get('neighbor_protocol'),
        'tooltip': _port_tooltip(interface),
    }


def _build_faceplate(interface_rows):
    candidates = [
        row for row in interface_rows
        if not _VIRTUAL_INTERFACE_RE.search(row.get('name') or '')
    ]

    numeric_max = 0
    for row in candidates:
        name = (row.get('name') or '').strip()
        if name.isdigit():
            numeric_max = max(numeric_max, int(name))
    numeric_threshold = 24 if numeric_max <= 24 else 48

    physical = []
    sfp = []
    for row in candidates:
        name = (row.get('name') or '').strip()
        if _SFP_INTERFACE_RE.search(name):
            sfp.append(row)
        elif name.isdigit() and int(name) > numeric_threshold:
            sfp.append(row)
        else:
            physical.append(row)

    physical.sort(key=lambda row: _natural_sort_key(row.get('name')))
    sfp.sort(key=lambda row: _natural_sort_key(row.get('name')))

    physical_ports = [
        _faceplate_port(row, _port_number(row.get('name'), index + 1))
        for index, row in enumerate(physical)
    ]
    sfp_ports = [
        _faceplate_port(row, _port_number(row.get('name'), index + 1))
        for index, row in enumerate(sfp)
    ]

    pairs = []
    for index in range(0, len(physical_ports), 2):
        pairs.append({
            'top': physical_ports[index],
            'bottom': physical_ports[index + 1] if index + 1 < len(physical_ports) else None,
        })

    groups = [
        {'pairs': pairs[index:index + _FACEPLATE_GROUP_SIZE]}
        for index in range(0, len(pairs), _FACEPLATE_GROUP_SIZE)
    ]

    total = len(physical_ports) + len(sfp_ports)
    return {
        'faceplate_show': total >= 2,
        'faceplate_groups': groups,
        'faceplate_sfp_ports': sfp_ports,
        'faceplate_total': total,
        'faceplate_copper': len(physical_ports),
        'faceplate_up': sum(1 for port in physical_ports + sfp_ports if port['is_up']),
    }


def _chassis_model(device, latest, copper_total=0):
    device_type = getattr(device, 'device_type', None)
    model = (getattr(device_type, 'model', '') or '').strip() if device_type is not None else ''
    name = (getattr(device, 'name', '') or '').strip()
    if model:
        if copper_total and name:
            name_counts = {int(number) for number in re.findall(r'\d+', name)}
            if copper_total in name_counts and str(copper_total) not in model:
                return name.upper()
        return model.upper()
    if name:
        return name.upper()
    sys_descr = (latest.sys_descr if latest is not None else '') or ''
    summary = re.split(r'[\n,]', sys_descr, maxsplit=1)[0].strip()
    return (summary[:48] or 'Switch').upper()


def _vendor_theme(device, latest):
    device_type = getattr(device, 'device_type', None)
    manufacturer = getattr(device_type, 'manufacturer', None) if device_type is not None else None
    sys_descr = (latest.sys_descr if latest is not None else '') or ''
    haystack = ' '.join(
        filter(
            None,
            (
                getattr(manufacturer, 'slug', '') or '',
                getattr(manufacturer, 'name', '') or '',
                getattr(device_type, 'model', '') or '',
                sys_descr,
            ),
        )
    ).lower()

    for theme, keywords in _VENDOR_THEMES:
        for keyword in keywords:
            if keyword == 'hp':
                if re.search(r'\bhp\b', haystack):
                    return theme
            elif keyword in haystack:
                return theme
    return 'default'


def _sla_badge_class(sla_percent):
    if sla_percent is None:
        return 'text-bg-secondary'
    if sla_percent >= 99:
        return 'text-bg-success'
    if sla_percent >= 95:
        return 'text-bg-warning'
    return 'text-bg-danger'


def _monitored_devices(request):
    return list(
        Device.objects.restrict(request.user, 'view')
        .filter(Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False))
        .select_related(
            'primary_ip4', 'primary_ip6', 'site', 'rack', 'role',
            'device_type', 'device_type__manufacturer',
        )
        .order_by('name')
    )


def _build_noc_rows(devices):
    latest_metrics = {
        metric.device_id: metric
        for metric in DeviceMetric.objects.filter(device__in=devices)
        .order_by('device_id', '-timestamp')
        .distinct('device_id')
    }

    previous_metrics = {
        metric.device_id: metric
        for metric in DeviceMetric.objects.filter(device__in=devices)
        .exclude(pk__in=[metric.pk for metric in latest_metrics.values()])
        .order_by('device_id', '-timestamp')
        .distinct('device_id')
    }

    sla_stats = {
        item['device_id']: item
        for item in DeviceMetric.objects.filter(
            device__in=devices,
            timestamp__gte=timezone.now() - _SLA_WINDOW,
        )
        .values('device_id')
        .annotate(
            total=Count('id'),
            online=Count('id', filter=Q(is_online=True)),
        )
    }

    rows = []
    for device in devices:
        metric = latest_metrics.get(device.pk)
        previous = previous_metrics.get(device.pk)
        interface_rows = _interfaces_with_rates(metric, previous)
        physical_rows = _physical_interface_rows(interface_rows)

        stats = sla_stats.get(device.pk)
        sla_percent = None
        if stats and stats['total']:
            sla_percent = round(stats['online'] / stats['total'] * 100, 2)

        poe = _poe_summary(
            metric.hardware_metrics if metric is not None else None
        )
        poe_used = poe['used_watts'] if poe else None
        poe_budget = poe['budget_watts'] if poe else None

        traffic_download_mbps = 0.0
        traffic_upload_mbps = 0.0
        has_traffic = False
        for interface_row in interface_rows:
            traffic_download = interface_row.get('download_mbps')
            traffic_upload = interface_row.get('upload_mbps')
            if traffic_download is not None:
                traffic_download_mbps += float(traffic_download)
                has_traffic = True
            if traffic_upload is not None:
                traffic_upload_mbps += float(traffic_upload)
                has_traffic = True
        device_download_mbps = (
            round(traffic_download_mbps, 3) if has_traffic else None
        )
        device_upload_mbps = round(traffic_upload_mbps, 3) if has_traffic else None

        port_percent = None
        if physical_rows:
            port_percent = round(
                sum(
                    1 for row in physical_rows
                    if (row.get('status') or '').upper() == 'UP'
                ) / len(physical_rows) * 100,
                1,
            )

        loop_alert = _loop_flag(metric)

        rows.append({
            'device': device,
            'ip': str(device.primary_ip.address).split('/')[0] if device.primary_ip else '',
            'metric': metric,
            'status': 'ONLINE' if (metric and metric.is_online) else 'OFFLINE',
            'is_online': bool(metric and metric.is_online),
            'has_latency': bool(metric and metric.latency_ms is not None),
            'latency_ms': metric.latency_ms if metric else None,
            'uptime': _format_uptime(metric),
            'active_ports': sum(
                1 for row in physical_rows
                if (row.get('status') or '').upper() == 'UP'
            ),
            'total_ports': len(physical_rows),
            'port_percent': port_percent,
            'traffic_total': _aggregate_traffic(interface_rows),
            'download_mbps': device_download_mbps,
            'upload_mbps': device_upload_mbps,
            'loop_alert': loop_alert,
            'stp_alert': loop_alert,
            'poe_used': poe_used,
            'poe_budget': poe_budget,
            'sla_percent': sla_percent,
            'sla_badge_class': _sla_badge_class(sla_percent),
        })
    return rows


class MonitorView(View):
    def get(self, request):
        plugin_config = apps.get_app_config('netbox_monitor')

        devices = _monitored_devices(request)
        rows = _build_noc_rows(devices)

        online = sum(1 for row in rows if row['is_online'])
        incidents = _build_recent_incidents(
            devices,
            timezone.now() - _INCIDENT_WINDOW,
        )

        return render(
            request,
            'netbox_monitor/monitor.html',
            {
                'plugin_name': plugin_config.verbose_name,
                'plugin_version': plugin_config.version,
                'rows': rows,
                'total': len(rows),
                'online': online,
                'offline': len(rows) - online,
                'incidents': incidents,
            },
        )


class ExportNocCsvView(View):
    def get(self, request):
        devices = _monitored_devices(request)
        rows = _build_noc_rows(devices)

        response = HttpResponse(content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = (
            'attachment; filename="netbox_monitor_sla.csv"'
        )

        writer = csv.writer(response)
        writer.writerow([
            'Dispositivo',
            'IP',
            'Status',
            'Latencia_ms',
            'Uptime',
            'Portas_Ativas',
            'Trafego_Mbps',
            'Loop_STP',
            'SLA_7d',
        ])
        for row in rows:
            metric = row['metric']
            if row['stp_alert'] is None:
                loop_stp = ''
            else:
                loop_stp = 'ALERTA' if row['stp_alert'] else 'Normal'
            writer.writerow([
                str(row['device']),
                row['ip'],
                'ONLINE' if row['is_online'] else 'OFFLINE',
                metric.latency_ms if metric and metric.latency_ms is not None else '',
                row['uptime'] if metric else '',
                row['active_ports'] if metric else '',
                row['traffic_total'] if row['traffic_total'] is not None else '',
                loop_stp,
                f"{row['sla_percent']:.2f}" if row['sla_percent'] is not None else '',
            ])

        return response


class MonitorSettingsView(LoginRequiredMixin, View):
    template_name = 'netbox_monitor/settings.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and not (
            request.user.is_superuser
            or request.user.has_perm('netbox_monitor.change_monitorsettings')
        ):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = MonitorSettingsForm(instance=MonitorSettings.get_solo())
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        settings_obj = MonitorSettings.get_solo()
        form = MonitorSettingsForm(request.POST, instance=settings_obj)

        if not form.is_valid():
            messages.error(
                request,
                _('Não foi possível salvar as configurações. Verifique os campos.'),
            )
            return render(request, self.template_name, {'form': form})

        form.save()

        if request.POST.get('action') == 'test':
            sent = send_webhook_alert(
                '🔔 Teste de alerta do NetBox Monitor realizado com sucesso!'
            )
            if sent:
                messages.success(
                    request,
                    _('Teste de alerta enviado com sucesso.'),
                )
            elif not settings_obj.enabled:
                messages.error(
                    request,
                    _('Os alertas estão desativados. Ative-os para testar.'),
                )
            elif not settings_obj.webhook_url:
                messages.error(
                    request,
                    _('Configure a URL do webhook para enviar o teste.'),
                )
            else:
                messages.error(
                    request,
                    _('Falha ao enviar o teste. Verifique a URL do webhook.'),
                )
        else:
            messages.success(request, _('Configurações salvas com sucesso.'))

        return redirect(reverse('plugins:netbox_monitor:settings'))


@register_model_view(Device, 'monitor', path='monitor')
class DeviceMonitorView(generic.ObjectView):
    queryset = Device.objects.all()
    template_name = 'netbox_monitor/device_monitor.html'
    tab = ViewTab(
        label=_('Monitoramento'),
        permission='dcim.view_device',
        weight=600,
    )

    def get_extra_context(self, request, instance):
        range_key = request.GET.get('range', _DEFAULT_RANGE)
        if range_key not in _RANGE_MAP:
            range_key = _DEFAULT_RANGE
        range_delta, range_label = _RANGE_MAP[range_key]

        start = timezone.now() - range_delta
        metrics = list(
            DeviceMetric.objects.filter(
                device=instance,
                timestamp__gte=start,
            ).order_by('timestamp')
        )
        chart_metrics = _downsample(metrics)
        latest = metrics[-1] if metrics else None
        previous = metrics[-2] if len(metrics) > 1 else None

        interface_rows = _interfaces_with_rates(latest, previous)
        vendor_theme = _vendor_theme(instance, latest)

        has_resource_data = latest is not None and (
            latest.cpu_percent is not None or latest.memory_percent is not None
        )
        has_resource_history = any(
            metric.cpu_percent is not None or metric.memory_percent is not None
            for metric in chart_metrics
        )
        traffic_chart_values = _traffic_series(chart_metrics)
        has_traffic_history = any(value is not None for value in traffic_chart_values)
        port_history = _port_history_series(chart_metrics)

        physical_interface_rows = _physical_interface_rows(interface_rows)
        active_ports = sum(
            1 for row in physical_interface_rows
            if (row.get('status') or '').upper() == 'UP'
        )
        total_ports = len(physical_interface_rows)
        total_traffic_mbps = _aggregate_traffic(interface_rows)

        vlans_summary = []
        loop_status = {}
        if latest is not None:
            if isinstance(latest.vlans_summary, list):
                vlans_summary = latest.vlans_summary
            if isinstance(latest.loop_status, dict):
                loop_status = latest.loop_status

        hardware_metrics = {}
        if latest is not None and isinstance(latest.hardware_metrics, dict):
            hardware_metrics = latest.hardware_metrics

        poe = _poe_summary(hardware_metrics)
        interface_rows = _annotate_poe(interface_rows, hardware_metrics)
        interface_rows = _annotate_neighbors(interface_rows, hardware_metrics)

        temperatures = []
        for item in hardware_metrics.get('temperatures', []) or []:
            if not isinstance(item, dict):
                continue
            temperatures.append({
                'name': item.get('name') or 'Sensor',
                'value_c': item.get('value_c'),
                'badge_class': _temperature_badge_class(item.get('value_c')),
            })
        fans = []
        for item in hardware_metrics.get('fans', []) or []:
            if not isinstance(item, dict):
                continue
            fans.append({
                'name': item.get('name') or 'Ventoinha',
                'rpm': item.get('rpm'),
                'status': item.get('status') or '—',
                'badge_class': _fan_badge_class(item.get('status')),
            })

        has_temperatures = bool(temperatures)
        has_fans = bool(fans)
        has_hardware_sensors = has_temperatures or has_fans
        max_temperature = None
        if has_temperatures:
            temperature_values = [
                item['value_c'] for item in temperatures
                if isinstance(item['value_c'], (int, float))
            ]
            if temperature_values:
                max_temperature = max(temperature_values)

        faceplate = _build_faceplate(interface_rows)

        return {
            'latest_metric': latest,
            'has_latency': latest is not None and latest.latency_ms is not None,
            'range_key': range_key,
            'range_label': range_label,
            'range_options': [
                {'key': key, 'label': key, 'active': key == range_key}
                for key, _delta, _label in _RANGE_OPTIONS
            ],
            'port_history_json': port_history,
            'interface_rows': interface_rows,
            'vlans_summary': vlans_summary,
            'loop_status': loop_status,
            'temperatures': temperatures,
            'fans': fans,
            'has_temperatures': has_temperatures,
            'has_fans': has_fans,
            'has_hardware_sensors': has_hardware_sensors,
            'max_temperature': max_temperature,
            'poe': poe,
            'chart_labels': [
                m.timestamp.strftime('%d/%m %H:%M:%S') for m in chart_metrics
            ],
            'chart_values': [m.latency_ms for m in chart_metrics],
            'cpu_chart_values': [m.cpu_percent for m in chart_metrics],
            'memory_chart_values': [m.memory_percent for m in chart_metrics],
            'traffic_chart_values': traffic_chart_values,
            'has_resource_data': has_resource_data,
            'has_resource_history': has_resource_history,
            'has_traffic_history': has_traffic_history,
            'show_traffic_chart': not has_resource_history and has_traffic_history,
            'active_ports': active_ports,
            'total_ports': total_ports,
            'total_traffic_mbps': total_traffic_mbps,
            'chassis_model': _chassis_model(
                instance, latest, faceplate['faceplate_copper']
            ),
            'vendor_theme': vendor_theme,
            'vendor_label': _VENDOR_LABELS.get(vendor_theme, 'Switch'),
            'vendor_has_console': vendor_theme in _VENDOR_CONSOLE_THEMES,
            **faceplate,
        }


def _collect_now(device, ip, community):
    data = collect_device(ip, community)
    save_metric(device, data)
    return data


class CollectNowView(View):
    def post(self, request, pk):
        device = get_object_or_404(
            Device.objects.restrict(request.user, 'view'),
            pk=pk,
        )
        redirect_url = reverse('dcim:device_monitor', kwargs={'pk': device.pk})

        if device.primary_ip is None:
            messages.warning(
                request,
                _('{device} não possui IP primário configurado.').format(device=device),
            )
            return redirect(redirect_url)

        ip = str(device.primary_ip.address).split('/')[0]
        community = device.cf.get('snmp_community') or 'public'

        try:
            data = _collect_now(device, ip, community)
        except Exception as exc:
            messages.warning(
                request,
                _('Falha ao coletar {device}: {error}').format(
                    device=device,
                    error=exc,
                ),
            )
        else:
            status = 'ONLINE' if data.get('is_online') else 'OFFLINE'
            messages.success(
                request,
                _('Coleta concluída para {device} ({status}).').format(
                    device=device,
                    status=status,
                ),
            )

        return redirect(redirect_url)


class SyncSnmpToNetboxView(LoginRequiredMixin, View):
    http_method_names = ['post']

    def post(self, request, pk):
        device = get_object_or_404(
            Device.objects.restrict(request.user, 'view'),
            pk=pk,
        )
        redirect_url = reverse('dcim:device_monitor', kwargs={'pk': device.pk})

        metric = (
            DeviceMetric.objects.filter(device=device)
            .exclude(interfaces_summary=[])
            .order_by('-timestamp')
            .first()
        )
        if metric is None or not metric.interfaces_summary:
            messages.warning(
                request,
                _(
                    '{device} não possui coleta SNMP com interfaces. '
                    'Execute uma coleta antes de sincronizar.'
                ).format(device=device),
            )
            return redirect(redirect_url)

        vlans_by_vid = {}
        vlans_created = 0
        vlans_existing = 0
        interfaces_created = 0
        interfaces_updated = 0

        with transaction.atomic():
            for item in metric.vlans_summary or []:
                try:
                    vid = int(item.get('vlan_id'))
                except (TypeError, ValueError, AttributeError):
                    continue

                vlan_name = (item.get('name') or '').strip() or f'VLAN {vid}'
                vlan, created = VLAN.objects.get_or_create(
                    vid=vid,
                    site=device.site,
                    defaults={'name': vlan_name},
                )
                vlans_by_vid[vid] = vlan
                if created:
                    vlans_created += 1
                else:
                    vlans_existing += 1

            for item in metric.interfaces_summary or []:
                port_name = str(item.get('name') or '').strip()
                if not port_name or _VIRTUAL_INTERFACE_RE.search(port_name):
                    continue

                is_up = (item.get('status') or '').upper() == 'UP'
                if_type = _sync_interface_type(port_name)

                iface, created = Interface.objects.get_or_create(
                    device=device,
                    name=port_name,
                    defaults={'type': if_type, 'enabled': is_up},
                )
                update_fields = []
                if created:
                    interfaces_created += 1
                else:
                    interfaces_updated += 1
                    if iface.enabled != is_up:
                        iface.enabled = is_up
                        update_fields.append('enabled')

                pvid = item.get('pvid')
                if pvid is not None:
                    try:
                        pvid = int(pvid)
                    except (TypeError, ValueError):
                        pvid = None
                vlan = vlans_by_vid.get(pvid) if pvid is not None else None
                if vlan is not None:
                    if iface.untagged_vlan_id != vlan.pk:
                        iface.untagged_vlan = vlan
                        update_fields.append('untagged_vlan')
                    if iface.mode != 'access':
                        iface.mode = 'access'
                        update_fields.append('mode')

                if update_fields:
                    iface.save(update_fields=update_fields)

        messages.success(
            request,
            _(
                'Sincronização concluída para {device}: '
                '{iface_created} interface(s) criada(s), '
                '{iface_updated} atualizada(s); '
                '{vlan_created} VLAN(s) criada(s), '
                '{vlan_existing} já existente(s).'
            ).format(
                device=device,
                iface_created=interfaces_created,
                iface_updated=interfaces_updated,
                vlan_created=vlans_created,
                vlan_existing=vlans_existing,
            ),
        )
        return redirect(redirect_url)


class CollectAllView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        import threading
        from django.db import close_old_connections
        from django.test import RequestFactory
        from dcim.models import Device

        user = request.user

        def _bg_worker():
            rf = RequestFactory()
            devs = (Device.objects.filter(primary_ip4__isnull=False) | Device.objects.filter(primary_ip6__isnull=False)).distinct().order_by('name')
            total = devs.count()
            print(f'[NetBox Monitor] Iniciando coleta completa de {total} dispositivos...', flush=True)
            for idx, d in enumerate(devs, 1):
                try:
                    fake_req = rf.post(f'/plugins/monitor/device/{d.pk}/collect/')
                    fake_req.user = user
                    from django.contrib.messages.storage.fallback import FallbackStorage
                    setattr(fake_req, 'session', 'session')
                    setattr(fake_req, '_messages', FallbackStorage(fake_req))
                    CollectNowView.as_view()(fake_req, pk=d.pk)
                    print(f'[NetBox Monitor] [{idx}/{total}] {d.name} OK', flush=True)
                except Exception as ex:
                    print(f'[NetBox Monitor] [{idx}/{total}] {d.name} aviso: {ex}', flush=True)
            close_old_connections()
            print('[NetBox Monitor] Coleta em lote finalizada!', flush=True)

        threading.Thread(target=_bg_worker, daemon=True).start()
        messages.success(request, 'Coleta em lote iniciada em segundo plano! Atualize a pagina em ~15 segundos.')
        return redirect('login')

class NocTvDashboardView(LoginRequiredMixin, View):
    def get(self, request):
        plugin_config = apps.get_app_config('netbox_monitor')
        all_devices = _monitored_devices(request)

        site = (request.GET.get('site') or '').strip()
        device_id = (request.GET.get('device') or '').strip()
        minutes = _tv_range_minutes(request)

        site_options = _tv_site_options(all_devices)
        scoped_devices = _tv_filter_devices(all_devices, site, '')
        device_options = _tv_device_options(scoped_devices)
        devices = _tv_filter_devices(all_devices, site, device_id)

        rows = _build_noc_rows(devices)
        device_rows = _tv_device_rows(rows)

        online_devices = sum(1 for row in rows if row['is_online'])
        offline_devices = sum(
            1 for row in rows if row['metric'] is not None and not row['is_online']
        )
        no_data_devices = sum(1 for row in rows if row['metric'] is None)

        total_traffic = sum(
            row['traffic_total'] for row in rows
            if row['traffic_total'] is not None
        )

        avg_cpu = _tv_avg([row['cpu'] for row in device_rows])
        avg_memory = _tv_avg([row['memory'] for row in device_rows])
        avg_ports = _tv_avg([row['port_percent'] for row in device_rows])
        avg_sla = _tv_avg([row['sla_percent'] for row in device_rows])
        stp_alerts = sum(1 for row in rows if row['stp_alert'])

        now = timezone.now()
        events = _build_recent_incidents(
            devices,
            now - _INCIDENT_WINDOW,
            limit=500,
        )

        trend = _tv_trend_series(devices, minutes)
        availability = _tv_availability(devices)

        latency_bars = sorted(
            [
                {
                    'label': row['name'],
                    'value': row['latency_ms'],
                    'unit': ' ms',
                }
                for row in device_rows
                if row['latency_ms'] is not None
            ],
            key=lambda item: item['value'],
            reverse=True,
        )[:8]

        top_devices = sorted(
            [row for row in device_rows if row['has_metric']],
            key=lambda row: (
                row['cpu'] if row['cpu'] is not None else -1,
                row['memory'] if row['memory'] is not None else -1,
                row['traffic_total'] if row['traffic_total'] is not None else -1,
            ),
            reverse=True,
        )[:8]

        noc_data = {
            'generated_at': timezone.localtime(now).strftime('%d/%m/%Y %H:%M:%S'),
            'filters': {
                'site': site,
                'device': device_id,
                'range': str(minutes),
            },
            'sites': site_options,
            'device_options': device_options,
            'summary': {
                'total': len(rows),
                'online': online_devices,
                'offline': offline_devices,
                'no_data': no_data_devices,
                'sla': avg_sla,
                'stp_alerts': stp_alerts,
                'traffic_total': round(total_traffic, 2),
            },
            'gauges': {
                'cpu': avg_cpu,
                'memory': avg_memory,
                'ports': avg_ports,
                'sla': avg_sla,
            },
            'status_donut': [
                {'label': 'Online', 'value': online_devices, 'color': '#73bf69'},
                {'label': 'Offline', 'value': offline_devices, 'color': '#f2495c'},
                {'label': 'Sem dados', 'value': no_data_devices, 'color': '#5794f2'},
            ],
            'trend': trend,
            'availability': availability,
            'latency_bars': latency_bars,
            'devices': device_rows,
            'top_devices': top_devices,
            'alerts_hour': _tv_alerts_by_hour(events, now),
            'incidents': _tv_incident_payload(events[:50]),
        }

        return render(
            request,
            'netbox_monitor/noc_tv.html',
            {
                'plugin_name': plugin_config.verbose_name,
                'plugin_version': plugin_config.version,
                'sites': site_options,
                'device_options': device_options,
                'selected_site': site,
                'selected_device': device_id,
                'selected_range': str(minutes),
                'noc_data': noc_data,
            },
        )


_TOPOLOGY_DEFAULT_RACK = 'Sem Rack / Geral'
_TOPOLOGY_EXTERNAL_RACK = 'Externo / Não cadastrado'
_TOPOLOGY_ROLE_SLUGS = {
    'swt': 'switch',
    'sw': 'switch',
    'switch': 'switch',
    'rtr': 'router',
    'router': 'router',
    'fw': 'firewall',
    'firewall': 'firewall',
    'srv': 'server',
    'server': 'server',
    'ap': 'ap',
    'wifi': 'ap',
    'wireless': 'ap',
}
_TOPOLOGY_ROLE_KEYWORDS = (
    ('firewall', ('firewall', 'fortigate', 'pfsense', 'sonicwall', 'fw-')),
    ('router', ('router', 'gateway', 'edge-switch', 'routeros')),
    ('ap', ('access point', 'wireless', 'unifi', 'wifi', 'ap-', '-ap')),
    ('server', ('server', 'esxi', 'hypervisor', 'nas', 'srv')),
    (
        'switch',
        ('switch', 'catalyst', 'aruba', 'procurve', 'edgeswitch', 'poe'),
    ),
)
_CABLE_SPEED_KEYWORDS = (
    ('100g', 100000),
    ('40g', 40000),
    ('25g', 25000),
    ('10g', 10000),
    ('5g', 5000),
    ('2.5g', 2500),
    ('1000base', 1000),
    ('1g', 1000),
    ('100base', 100),
)


def _topology_role(device):
    role = getattr(device, 'role', None)
    slug = (getattr(role, 'slug', '') or '').strip().lower()
    mapped = _TOPOLOGY_ROLE_SLUGS.get(slug)
    if mapped:
        return mapped
    haystack = ' '.join(
        filter(
            None,
            (
                slug,
                getattr(role, 'name', '') or '',
                str(getattr(device, 'name', '') or ''),
                getattr(getattr(device, 'device_type', None), 'model', '') or '',
            ),
        )
    ).lower()
    for key, keywords in _TOPOLOGY_ROLE_KEYWORDS:
        if any(keyword in haystack for keyword in keywords):
            return key
    return 'switch'


def _topology_external_role(name):
    text = (name or '').lower()
    if any(
        key in text
        for key in ('ap-', '-ap', 'unifi', 'wifi', 'wireless', 'access point')
    ):
        return 'ap'
    if any(key in text for key in ('firewall', 'fortigate', 'fw')):
        return 'firewall'
    if any(key in text for key in ('router', 'gateway', 'edge')):
        return 'router'
    if any(key in text for key in ('server', 'srv', 'esxi', 'nas')):
        return 'server'
    return 'switch'


def _topology_slug(value):
    slug = re.sub(r'[^a-z0-9]+', '-', (value or '').lower()).strip('-')
    return slug or 'externo'


def _topology_active_ports(metric):
    if metric is None:
        return 0
    rows = _physical_interface_rows(_interfaces_with_rates(metric, None))
    return sum(
        1 for row in rows if (row.get('status') or '').upper() == 'UP'
    )


def _topology_node_payload(device, metric=None, active_ports=None):
    if active_ports is None:
        active_ports = _topology_active_ports(metric)
    primary_ip = getattr(device, 'primary_ip', None)
    rack = getattr(device, 'rack', None)
    if metric is None:
        status = 'PENDING'
    elif metric.is_online:
        status = 'ONLINE'
    else:
        status = 'OFFLINE'
    return {
        'id': str(device.pk),
        'name': str(device.name),
        'ip': str(primary_ip.address).split('/')[0] if primary_ip else '',
        'rack': getattr(rack, 'name', None) or _TOPOLOGY_DEFAULT_RACK,
        'role': _topology_role(device),
        'status': status,
        'active_ports': int(active_ports or 0),
        'url': reverse('dcim:device_monitor', kwargs={'pk': device.pk}),
        'external': False,
    }


def _topology_external_node(name, node_id):
    return {
        'id': node_id,
        'name': name,
        'ip': '',
        'rack': _TOPOLOGY_EXTERNAL_RACK,
        'role': _topology_external_role(name),
        'status': 'ONLINE',
        'active_ports': 0,
        'url': '',
        'external': True,
    }


def _interface_speed_map(metric):
    speeds = {}
    if metric is None:
        return speeds
    for interface in metric.interfaces_summary or []:
        name = (interface.get('name') or '').strip()
        speed = interface.get('speed_mbps')
        if not name or speed is None:
            continue
        try:
            speed = int(float(speed))
        except (TypeError, ValueError):
            continue
        if speed <= 0:
            continue
        speeds.setdefault(name.lower(), speed)
        normalized = re.sub(r'[^a-z0-9]', '', name.lower())
        if normalized:
            speeds.setdefault(normalized, speed)
    return speeds


def _cable_speed_mbps(cable):
    text = ' '.join(
        str(part or '')
        for part in (
            getattr(cable, 'type', ''),
            getattr(cable, 'label', ''),
            getattr(cable, 'description', ''),
        )
    ).lower()
    for keyword, speed in _CABLE_SPEED_KEYWORDS:
        if keyword in text:
            return speed
    return None


def _topology_cable_links(devices):
    if not devices:
        return []
    interfaces = Interface.objects.filter(device__in=devices).values(
        'pk', 'device_id', 'name'
    )
    interface_map = {item['pk']: item for item in interfaces}
    if not interface_map:
        return []

    interface_ct = ContentType.objects.get_for_model(Interface)
    terminations = CableTermination.objects.filter(
        termination_type=interface_ct,
        termination_id__in=interface_map.keys(),
    ).select_related('cable')

    cables = {}
    for termination in terminations:
        cables.setdefault(termination.cable_id, {})[
            termination.cable_end
        ] = termination

    rows = []
    for entries in cables.values():
        term_a = entries.get('A')
        term_b = entries.get('B')
        if term_a is None or term_b is None:
            continue
        iface_a = interface_map.get(term_a.termination_id)
        iface_b = interface_map.get(term_b.termination_id)
        if iface_a is None or iface_b is None:
            continue
        if iface_a['device_id'] == iface_b['device_id']:
            continue
        rows.append((
            str(iface_a['device_id']),
            str(iface_b['device_id']),
            iface_a['name'] or '',
            iface_b['name'] or '',
            _cable_speed_mbps(term_a.cable),
            'NetBox Cable',
        ))
    return rows


def _topology_site_options(devices):
    sites = {}
    for device in devices:
        site = getattr(device, 'site', None)
        if site is None:
            continue
        sites[str(site.pk)] = {
            'id': str(site.pk),
            'slug': site.slug,
            'name': site.name,
        }
    return [
        sites[key]
        for key in sorted(sites, key=lambda item: sites[item]['name'].lower())
    ]


def _filter_topology_devices(devices, site):
    if not site:
        return devices
    return [
        device for device in devices
        if getattr(device, 'site', None) is not None
        and (str(device.site_id) == site or device.site.slug == site)
    ]


class TopologyView(View):
    def get(self, request):
        plugin_config = apps.get_app_config('netbox_monitor')
        all_devices = _monitored_devices(request)
        site_options = _topology_site_options(all_devices)
        site_param = (request.GET.get('site') or '').strip()
        devices = _filter_topology_devices(all_devices, site_param)
        rows = _build_noc_rows(devices)

        nodes = []
        nodes_by_id = {}

        def _register(node):
            if node['id'] in nodes_by_id:
                return
            nodes_by_id[node['id']] = node
            nodes.append(node)

        for row in rows:
            _register(_topology_node_payload(
                row['device'],
                row['metric'],
                row['active_ports'],
            ))

        all_by_id = {str(device.pk): device for device in all_devices}
        name_index = {
            str(device.name or '').strip().lower(): str(device.pk)
            for device in all_devices
            if str(device.name or '').strip()
        }

        links = {}

        def _add_link(source, target, source_port, target_port, speed, protocol):
            if not source or not target or source == target:
                return
            key = (source, target) if source < target else (target, source)
            if source == key[0]:
                s_port, t_port = source_port, target_port
            else:
                s_port, t_port = target_port, source_port
            link = links.get(key)
            if link is None:
                links[key] = {
                    'source': key[0],
                    'target': key[1],
                    'source_port': s_port or '',
                    'target_port': t_port or '',
                    'speed_mbps': speed,
                    'protocol': protocol,
                }
                return
            if s_port:
                link['source_port'] = s_port
            if t_port:
                link['target_port'] = t_port
            if speed and (
                link.get('speed_mbps') is None
                or speed > link['speed_mbps']
            ):
                link['speed_mbps'] = speed
            if protocol in ('LLDP', 'CDP'):
                link['protocol'] = protocol

        for cable_link in _topology_cable_links(devices):
            _add_link(*cable_link)

        metric_cache = {}

        def _metric_for(device):
            if device.pk not in metric_cache:
                metric_cache[device.pk] = (
                    DeviceMetric.objects.filter(device=device)
                    .order_by('-timestamp')
                    .first()
                )
            return metric_cache[device.pk]

        for row in rows:
            device = row['device']
            source_id = str(device.pk)
            metric = row['metric']
            hardware = (
                metric.hardware_metrics
                if metric is not None
                and isinstance(metric.hardware_metrics, dict)
                else {}
            )
            neighbors = hardware.get('neighbors')
            if not isinstance(neighbors, list):
                continue
            speeds = _interface_speed_map(metric)
            for neighbor in neighbors:
                if not isinstance(neighbor, dict):
                    continue
                remote_name = str(neighbor.get('remote_device') or '').strip()
                if not remote_name:
                    continue
                remote_id = name_index.get(remote_name.lower())
                if remote_id is None:
                    remote_id = name_index.get(
                        re.sub(r'\..*$', '', remote_name).lower()
                    )
                if remote_id is not None and remote_id not in nodes_by_id:
                    remote_device = all_by_id.get(remote_id)
                    if remote_device is not None:
                        _register(_topology_node_payload(
                            remote_device,
                            _metric_for(remote_device),
                        ))
                if remote_id is None:
                    remote_id = f'ext:{_topology_slug(remote_name)}'
                    _register(_topology_external_node(remote_name, remote_id))
                local_port = str(neighbor.get('local_port') or '').strip()
                speed = speeds.get(local_port.lower())
                if speed is None:
                    speed = speeds.get(
                        re.sub(r'[^a-z0-9]', '', local_port.lower())
                    )
                _add_link(
                    source_id,
                    remote_id,
                    local_port,
                    str(neighbor.get('remote_port') or ''),
                    speed,
                    neighbor.get('protocol') or 'LLDP',
                )

        topology_data = {
            'nodes': nodes,
            'links': list(links.values()),
            'site': site_param,
        }

        return render(
            request,
            'netbox_monitor/topology.html',
            {
                'plugin_name': plugin_config.verbose_name,
                'plugin_version': plugin_config.version,
                'sites': site_options,
                'selected_site': site_param,
                'topology_data': topology_data,
                'node_count': len(nodes),
                'link_count': len(links),
            },
        )
