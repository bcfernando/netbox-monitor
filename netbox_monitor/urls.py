from django.urls import path

from . import views

urlpatterns = [
    path('', views.MonitorView.as_view(), name='monitor'),
    path('settings/', views.MonitorSettingsView.as_view(), name='settings'),
    path('services/', views.ServicesView.as_view(), name='services'),
    path('topology/', views.TopologyView.as_view(), name='topology'),
    path('topology/sync-cables/', views.SyncLldpCablesView.as_view(), name='topology_sync_cables'),
    path('collect-all/', views.CollectAllView.as_view(), name='collect_all'),
    path('export/csv/', views.ExportNocCsvView.as_view(), name='export_csv'),
    path('devices/<int:pk>/collect/', views.CollectNowView.as_view(), name='device_collect'),
    path('device/<int:pk>/sync/', views.SyncSnmpToNetboxView.as_view(), name='device_sync'),
    path('api/live/', views.LiveMetricsApiView.as_view(), name='live'),
    path('tv/', views.NocTvDashboardView.as_view(), name='tv'),
]
