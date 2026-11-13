from django.urls import path

from . import views

urlpatterns = [
    path('', views.MonitorView.as_view(), name='monitor'),
    path('collect-all/', views.CollectAllView.as_view(), name='collect_all'),
    path('devices/<int:pk>/collect/', views.CollectNowView.as_view(), name='device_collect'),
]
