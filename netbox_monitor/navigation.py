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
            ),
        ),
    ),
    icon_class='mdi mdi-monitor-dashboard',
)
