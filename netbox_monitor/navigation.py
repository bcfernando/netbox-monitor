from netbox.plugins import PluginMenu, PluginMenuItem

menu = PluginMenu(
    label='Monitoramento',
    groups=(
        (
            'Monitoramento',
            (
                PluginMenuItem(
                    link='plugins:netbox_monitor:monitor',
                    link_text='Visão Geral',
                ),
                PluginMenuItem(
                    link='plugins:netbox_monitor:services',
                    link_text='Serviços & SSL',
                ),
                PluginMenuItem(
                    link='plugins:netbox_monitor:topology',
                    link_text='Topologia',
                ),
                PluginMenuItem(
                    link='plugins:netbox_monitor:settings',
                    link_text='Configurações',
                ),
            ),
        ),
    ),
    icon_class='mdi mdi-monitor-dashboard',
)
