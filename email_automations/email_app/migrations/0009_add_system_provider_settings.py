# Generated manually
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('email_app', '0008_userprofile'),
    ]

    operations = [
        migrations.CreateModel(
            name='SystemProviderSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('provider_type', models.CharField(choices=[('spacemail', 'SpaceMail'), ('gmail', 'Gmail')], default='spacemail', max_length=20)),
                ('smtp_server', models.CharField(default='mail.spacemail.com', max_length=255)),
                ('smtp_port', models.IntegerField(default=465)),
                ('smtp_username', models.EmailField(max_length=254)),
                ('smtp_password', models.CharField(max_length=255)),
                ('is_active', models.BooleanField(default=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'System Provider Settings',
                'verbose_name_plural': 'System Provider Settings',
                'ordering': ['-updated_at'],
            },
        ),
    ]

