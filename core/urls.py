from django.urls import path

from core import views

urlpatterns = [
    path('', views.index),
    path('firewall_log/', views.firewallLog),
    path('ids_log/', views.idsLog),
    path('firewall_rule/', views.firewallRule),
    path('ids_rule/', views.idsRule),
    path('traffic_statistic/', views.trafficStatistic),

    path('submit/firewall_rule/', views.submitFirewallRule),
    path('submit/ids_rule/', views.submitIDSRule),
]