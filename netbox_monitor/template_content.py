from django.urls import reverse

from netbox.plugins import PluginTemplateExtension

from .models import DeviceMetric


class DeviceMonitorContent(PluginTemplateExtension):
    models = ['dcim.device']

    def right_page(self):
        obj = self.context['object']
        latest = DeviceMetric.objects.filter(device=obj).order_by('-timestamp').first()
        hardware_metrics = (
            latest.hardware_metrics
            if latest is not None and isinstance(latest.hardware_metrics, dict)
            else {}
        )
        ping_quality = hardware_metrics.get('ping_quality') or {}
        ping_packet_loss = (
            ping_quality.get('packet_loss') if isinstance(ping_quality, dict) else None
        )
        ping_jitter_ms = (
            ping_quality.get('jitter_ms') if isinstance(ping_quality, dict) else None
        )
        return self.render(
            'netbox_monitor/device_monitor_card.html',
            {
                'latest_metric': latest,
                'has_latency': latest is not None and latest.latency_ms is not None,
                'ping_packet_loss': ping_packet_loss,
                'ping_jitter_ms': ping_jitter_ms,
                'monitor_url': reverse('dcim:device_monitor', kwargs={'pk': obj.pk}),
            },
        )


template_extensions = [DeviceMonitorContent]
