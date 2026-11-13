from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_monitor', '0004_devicemetric_vlans_loop'),
    ]

    operations = [
        migrations.CreateModel(
            name='MonitorSettings',
            fields=[
                (
                    'id',
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name='ID',
                    ),
                ),
                (
                    'enabled',
                    models.BooleanField(
                        default=True,
                        verbose_name='Alertas Ativos',
                    ),
                ),
                (
                    'webhook_url',
                    models.URLField(
                        blank=True,
                        default='',
                        max_length=500,
                        verbose_name='URL do Webhook (Telegram / Discord / Slack / n8n)',
                    ),
                ),
                (
                    'telegram_chat_id',
                    models.CharField(
                        blank=True,
                        default='',
                        max_length=100,
                        verbose_name='Telegram Chat ID (opcional)',
                    ),
                ),
                (
                    'retention_days',
                    models.PositiveIntegerField(
                        default=30,
                        verbose_name='Retenção do Histórico (dias)',
                    ),
                ),
            ],
            options={
                'verbose_name': 'configuração do monitor',
                'verbose_name_plural': 'configurações do monitor',
            },
        ),
    ]
