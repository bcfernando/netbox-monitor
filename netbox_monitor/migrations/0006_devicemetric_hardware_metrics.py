from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_monitor', '0005_monitorsettings'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicemetric',
            name='hardware_metrics',
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
