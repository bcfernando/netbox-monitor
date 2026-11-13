import re

from django.apps import apps
from django.contrib import messages
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views import View

from dcim.models import Device
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

from .jobs import DeviceMonitorJob
from .models import DeviceMetric

_VIRTUAL_INTERFACE_RE = re.compile(
    r'(?:^|[^a-z])(?:loopback|lo|vlan|null|mgmt|trk|port-channel)\d*(?:[^a-z]|$)',
    re.IGNORECASE,
)
_SFP_INTERFACE_RE = re.compile(
    r'(?:sfp|ten|xfi|forty|hundred|25g|40g|100g)',
    re.IGNORECASE,
)
_FACEPLATE_GROUP_SIZE = 6

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


def _format_rate(value):
    if value is None:
        return '—'
    return f'{float(value):.2f} Mbps'


def _port_tooltip(interface):
    pvid = interface.get('pvid')
    return '{} | {} | VLAN (PVID): {} | STP: {} | Download: {} | Upload: {}'.format(
        interface.get('name') or '—',
        interface.get('status') or 'DOWN',
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
        'faceplate_up': sum(1 for port in physical_ports + sfp_ports if port['is_up']),
    }


def _chassis_model(device, latest):
    device_type = getattr(device, 'device_type', None)
    model = getattr(device_type, 'model', None) if device_type is not None else None
    if model:
        return model
    sys_descr = (latest.sys_descr if latest is not None else '') or ''
    summary = re.split(r'[\n,]', sys_descr, maxsplit=1)[0].strip()
    return summary[:48] or 'Switch'


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

        rows = []
        for device in devices:
            metric = latest_metrics.get(device.pk)
            rows.append({
                'device': device,
                'ip': str(device.primary_ip.address).split('/')[0] if device.primary_ip else '',
                'metric': metric,
                'is_online': bool(metric and metric.is_online),
                'has_latency': bool(metric and metric.latency_ms is not None),
            })

        online = sum(1 for row in rows if row['is_online'])

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
            },
        )


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
        metrics = list(
            DeviceMetric.objects.filter(device=instance).order_by('-timestamp')[:24]
        )
        metrics.reverse()
        latest = metrics[-1] if metrics else None
        previous = metrics[-2] if len(metrics) > 1 else None

        interface_rows = _interfaces_with_rates(latest, previous)
        vendor_theme = _vendor_theme(instance, latest)

        vlans_summary = []
        loop_status = {}
        if latest is not None:
            if isinstance(latest.vlans_summary, list):
                vlans_summary = latest.vlans_summary
            if isinstance(latest.loop_status, dict):
                loop_status = latest.loop_status

        return {
            'latest_metric': latest,
            'has_latency': latest is not None and latest.latency_ms is not None,
            'interface_rows': interface_rows,
            'vlans_summary': vlans_summary,
            'loop_status': loop_status,
            'chart_labels': [m.timestamp.strftime('%d/%m %H:%M:%S') for m in metrics],
            'chart_values': [m.latency_ms for m in metrics],
            'cpu_chart_values': [m.cpu_percent for m in metrics],
            'memory_chart_values': [m.memory_percent for m in metrics],
            'chassis_model': _chassis_model(instance, latest),
            'vendor_theme': vendor_theme,
            'vendor_label': _VENDOR_LABELS.get(vendor_theme, 'Switch'),
            'vendor_has_console': vendor_theme in _VENDOR_CONSOLE_THEMES,
            **_build_faceplate(interface_rows),
        }


class CollectNowView(View):
    def post(self, request, pk):
        device = get_object_or_404(
            Device.objects.restrict(request.user, 'view'),
            pk=pk,
        )
        job = DeviceMonitorJob.enqueue(
            user=request.user,
            name=f'Monitor {device}',
        )
        messages.success(
            request,
            _('Coleta enfileirada para {device} (Job #{id}).').format(
                device=device,
                id=job.pk,
            ),
        )
        return redirect(reverse('dcim:device_monitor', kwargs={'pk': device.pk}))


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
