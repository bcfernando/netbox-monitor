from django.db import models

from dcim.models import Device
from virtualization.models import VirtualMachine


class DeviceMetric(models.Model):
    device = models.ForeignKey(
        to=Device,
        on_delete=models.CASCADE,
        related_name='metrics',
    )
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    is_online = models.BooleanField(default=False)
    latency_ms = models.FloatField(null=True, blank=True)
    sys_descr = models.CharField(max_length=255, null=True, blank=True)
    uptime_seconds = models.BigIntegerField(null=True, blank=True)
    cpu_percent = models.FloatField(null=True, blank=True)
    memory_percent = models.FloatField(null=True, blank=True)
    interfaces_summary = models.JSONField(default=list, blank=True)
    vlans_summary = models.JSONField(default=list, blank=True)
    loop_status = models.JSONField(default=dict, blank=True)
    hardware_metrics = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('-timestamp',)
        verbose_name = 'métrica de dispositivo'
        verbose_name_plural = 'métricas de dispositivo'

    def __str__(self):
        return f'{self.device} @ {self.timestamp:%Y-%m-%d %H:%M:%S}'

    @property
    def uptime_display(self):
        if self.uptime_seconds is None:
            return None
        days, remainder = divmod(int(self.uptime_seconds), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        if days:
            return f'{days}d {hours}h {minutes}m'
        if hours:
            return f'{hours}h {minutes}m'
        if minutes:
            return f'{minutes}m {seconds}s'
        return f'{seconds}s'


class VirtualMachineMetric(models.Model):
    virtual_machine = models.ForeignKey(
        to=VirtualMachine,
        on_delete=models.CASCADE,
        related_name='metrics',
    )
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    is_online = models.BooleanField(default=False)
    latency_ms = models.FloatField(null=True, blank=True)
    sys_descr = models.CharField(max_length=255, null=True, blank=True)
    uptime_seconds = models.BigIntegerField(null=True, blank=True)
    cpu_percent = models.FloatField(null=True, blank=True)
    memory_percent = models.FloatField(null=True, blank=True)
    interfaces_summary = models.JSONField(default=list, blank=True)
    vlans_summary = models.JSONField(default=list, blank=True)
    loop_status = models.JSONField(default=dict, blank=True)
    hardware_metrics = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('-timestamp',)
        verbose_name = 'métrica de máquina virtual'
        verbose_name_plural = 'métricas de máquina virtual'

    def __str__(self):
        return f'{self.virtual_machine} @ {self.timestamp:%Y-%m-%d %H:%M:%S}'

    @property
    def uptime_display(self):
        if self.uptime_seconds is None:
            return None
        days, remainder = divmod(int(self.uptime_seconds), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        if days:
            return f'{days}d {hours}h {minutes}m'
        if hours:
            return f'{hours}h {minutes}m'
        if minutes:
            return f'{minutes}m {seconds}s'
        return f'{seconds}s'


class ServiceMonitor(models.Model):
    name = models.CharField(max_length=255)
    url = models.URLField(max_length=500)
    expected_keyword = models.CharField(max_length=200, blank=True, default='')
    virtual_machine = models.ForeignKey(
        to=VirtualMachine,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='service_monitors',
    )
    is_active = models.BooleanField(default=True)
    last_status = models.CharField(max_length=20, default='PENDING')
    http_code = models.IntegerField(null=True, blank=True)
    response_time_ms = models.FloatField(null=True, blank=True)
    ssl_days_remaining = models.IntegerField(null=True, blank=True)
    ssl_expires_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, default='')
    last_checked = models.DateTimeField(null=True, blank=True)
    last_ssl_alert_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ('name',)
        verbose_name = 'serviço monitorado'
        verbose_name_plural = 'serviços monitorados'

    def __str__(self):
        return f'{self.name} ({self.url})'

    @property
    def ssl_badge_class(self):
        if self.ssl_days_remaining is None:
            return 'text-bg-secondary'
        if self.ssl_days_remaining <= 0:
            return 'text-bg-danger'
        if self.ssl_days_remaining <= 15:
            return 'text-bg-warning'
        return 'text-bg-success'

    @property
    def status_badge_class(self):
        if self.last_status == 'ONLINE':
            return 'text-bg-success'
        if self.last_status == 'OFFLINE':
            return 'text-bg-danger'
        return 'text-bg-secondary'


class MonitorSettings(models.Model):
    enabled = models.BooleanField(
        default=True,
        verbose_name='Alertas Ativos',
    )
    webhook_url = models.URLField(
        max_length=500,
        blank=True,
        default='',
        verbose_name='URL do Webhook (Telegram / Discord / Slack / n8n)',
    )
    telegram_chat_id = models.CharField(
        max_length=100,
        blank=True,
        default='',
        verbose_name='Telegram Chat ID (opcional)',
    )
    retention_days = models.PositiveIntegerField(
        default=30,
        verbose_name='Retenção do Histórico (dias)',
    )
    latency_threshold_ms = models.PositiveIntegerField(
        default=150,
        verbose_name='Alerta de Latência Alta (ms) [0 = desativado]',
    )
    alert_on_uplink_down = models.BooleanField(
        default=True,
        verbose_name='Alertar queda de portas Uplink / SFP',
    )

    class Meta:
        verbose_name = 'configuração do monitor'
        verbose_name_plural = 'configurações do monitor'

    def __str__(self):
        return 'Configurações do NetBox Monitor'

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def get_solo(cls):
        from netbox.plugins import get_plugin_config

        try:
            retention_days = int(
                get_plugin_config('netbox_monitor', 'retention_days', 30)
            )
        except (TypeError, ValueError):
            retention_days = 30

        obj, _ = cls.objects.get_or_create(
            pk=1,
            defaults={
                'webhook_url': get_plugin_config(
                    'netbox_monitor', 'webhook_url', ''
                ) or '',
                'telegram_chat_id': get_plugin_config(
                    'netbox_monitor', 'telegram_chat_id', ''
                ) or '',
                'retention_days': retention_days,
            },
        )
        return obj
