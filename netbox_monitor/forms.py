from django import forms

from .models import MonitorSettings, ServiceMonitor


class MonitorSettingsForm(forms.ModelForm):
    class Meta:
        model = MonitorSettings
        fields = (
            'enabled',
            'webhook_url',
            'telegram_chat_id',
            'retention_days',
            'latency_threshold_ms',
            'alert_on_uplink_down',
        )


class ServiceMonitorForm(forms.ModelForm):
    class Meta:
        model = ServiceMonitor
        fields = (
            'name',
            'url',
            'expected_keyword',
            'virtual_machine',
            'is_active',
        )
