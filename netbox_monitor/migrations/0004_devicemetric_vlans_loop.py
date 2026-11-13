from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_monitor', '0003_devicemetric_cpu_memory'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicemetric',
            name='vlans_summary',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='devicemetric',
            name='loop_status',
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
