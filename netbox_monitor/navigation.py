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
                    link='plugins:netbox_monitor:settings',
                    link_text='Configurações',
                ),
            ),
        ),
    ),
    icon_class='mdi mdi-monitor-dashboard',
)
