from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_monitor', '0002_devicemetric_interfaces_summary_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicemetric',
            name='cpu_percent',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='devicemetric',
            name='memory_percent',
            field=models.FloatField(blank=True, null=True),
        ),
    ]
