from django.urls import reverse

from netbox.plugins import PluginTemplateExtension

from .models import DeviceMetric


class DeviceMonitorContent(PluginTemplateExtension):
    models = ['dcim.device']

    def right_page(self):
        obj = self.context['object']
        latest = DeviceMetric.objects.filter(device=obj).order_by('-timestamp').first()
        return self.render(
            'netbox_monitor/device_monitor_card.html',
            {
                'latest_metric': latest,
                'has_latency': latest is not None and latest.latency_ms is not None,
                'monitor_url': reverse('dcim:device_monitor', kwargs={'pk': obj.pk}),
            },
        )


template_extensions = [DeviceMonitorContent]
