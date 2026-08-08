"""Django URL configuration — test fixture for Django extractor tests."""

from django.urls import path, re_path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("users/", views.list_users, name="list_users"),
    path("users/<int:user_id>/", views.get_user, name="get_user"),
    path("users/<slug:username>/", views.user_profile, name="user_profile"),
    re_path(r"^api/v1/posts/$", views.api_posts, name="api_posts"),
    path("admin/dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("items/<uuid:item_id>/", views.item_detail, name="item_detail"),
]
