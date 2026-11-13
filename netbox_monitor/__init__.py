from netbox.plugins import PluginConfig


class NetBoxMonitorConfig(PluginConfig):
    name = 'netbox_monitor'
    verbose_name = 'NetBox Monitor'
    description = 'Monitoramento integrado estilo Zabbix/Grafana'
    version = '0.1.0'
    base_url = 'monitor'

    def ready(self):
        super().ready()
        from importlib import import_module

        import_module('netbox_monitor.jobs')


config = NetBoxMonitorConfig
