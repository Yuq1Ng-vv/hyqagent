"""Django views — test fixture for Django extractor tests."""

from django.contrib.auth.decorators import login_required, permission_required
from django.http import JsonResponse
from django.views.decorators.http import require_GET


def index(request):
    return JsonResponse({"status": "ok"})


def list_users(request):
    page = request.GET.get("page", 1)
    search = request.GET.get("q", "")
    return JsonResponse({"page": page, "search": search})


@login_required
def get_user(request, user_id):
    return JsonResponse({"id": user_id})


def user_profile(request, username):
    data = request.POST.get("bio")
    return JsonResponse({"username": username, "bio": data})


@require_GET
def api_posts(request):
    tag = request.GET.get("tag")
    return JsonResponse({"tag": tag})


@login_required
@permission_required("admin.view_dashboard")
def admin_dashboard(request):
    filter_val = request.GET.get("filter")
    body_data = request.body
    return JsonResponse({"filter": filter_val})


def item_detail(request, item_id):
    meta = request.META.get("HTTP_USER_AGENT")
    cookie_val = request.COOKIES.get("sessionid")
    return JsonResponse({"id": item_id, "meta": meta, "cookie": cookie_val})
