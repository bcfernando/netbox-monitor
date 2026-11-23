from netbox.plugins import PluginConfig


class NetBoxMonitorConfig(PluginConfig):
    name = 'netbox_monitor'
    verbose_name = 'NetBox Monitor'
    description = 'Monitoramento integrado estilo Zabbix/Grafana'
    version = '0.1.0'
    base_url = 'monitor'
    default_settings = {
        'webhook_url': '',
        'telegram_chat_id': '',
        'retention_days': 30,
    }

    def ready(self):
        super().ready()
        from importlib import import_module

        jobs = import_module('netbox_monitor.jobs')
        if jobs.should_start_fast_ping_daemon():
            jobs.start_fast_ping_daemon()


config = NetBoxMonitorConfig
