from django import forms

from .models import MonitorSettings


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
