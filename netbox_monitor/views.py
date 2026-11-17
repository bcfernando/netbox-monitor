import re
from datetime import timedelta

from django.apps import apps
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views import View

from dcim.models import Device, Interface
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


def _port_tooltip(interface):
    pvid = interface.get('pvid')
    is_up = (interface.get('status') or 'DOWN').upper() == 'UP'
    speed = _format_speed(interface.get('speed_mbps')) if is_up else None
    return (
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


def _faceplate_port(interface, number):
    status = (interface.get('status') or 'DOWN').upper()
    stp_state = (interface.get('stp_state') or '').upper()
    return {
        'name': interface.get('name') or '',
        'status': status,
        'is_up': status == 'UP',
        'number': number,
        'pvid': interface.get('pvid'),
        'stp_state': stp_state,
        'is_loop': stp_state in ('BLOCKING', 'BROKEN'),
        'speed_display': interface.get('speed_display'),
        'download_mbps': interface.get('download_mbps'),
        'upload_mbps': interface.get('upload_mbps'),
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


class MonitorView(View):
    def get(self, request):
        plugin_config = apps.get_app_config('netbox_monitor')

        devices = list(
            Device.objects.restrict(request.user, 'view')
            .filter(Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False))
            .select_related('primary_ip4', 'primary_ip6')
            .order_by('name')
        )

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

        rows = []
        for device in devices:
            metric = latest_metrics.get(device.pk)
            previous = previous_metrics.get(device.pk)
            interface_rows = _interfaces_with_rates(metric, previous)
            physical_rows = _physical_interface_rows(interface_rows)

            rows.append({
                'device': device,
                'ip': str(device.primary_ip.address).split('/')[0] if device.primary_ip else '',
                'metric': metric,
                'is_online': bool(metric and metric.is_online),
                'has_latency': bool(metric and metric.latency_ms is not None),
                'uptime': _format_uptime(metric),
                'active_ports': sum(
                    1 for row in physical_rows
                    if (row.get('status') or '').upper() == 'UP'
                ),
                'total_ports': len(physical_rows),
                'traffic_total': _aggregate_traffic(interface_rows),
                'stp_alert': _loop_flag(metric),
            })

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


class CollectAllView(View):
    def post(self, request):
        if not request.user.is_authenticated:
            return redirect('login')

        job = DeviceMonitorJob.enqueue(
            user=request.user,
            name='Monitor all devices',
        )
        messages.success(
            request,
            _('Coleta de todos os dispositivos enfileirada (Job #{id}).').format(id=job.pk),
        )
        return redirect(reverse('plugins:netbox_monitor:monitor'))
