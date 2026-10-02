from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("scan/", views.scan_view, name="scan_view"),  # <--- เพิ่มบรรทัดนี้
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("register/", views.register_view, name="register"),
    path("forgot-password/", views.forgot_password_view, name="forgot_password"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path(
        "statistics/report.pdf",
        views.statistics_pdf_view,
        name="statistics_pdf",
    ),
    path("admin/", views.admin_view, name="admin"),
    path("admin/users/<int:user_id>/toggle/", views.admin_toggle_user, name="admin_toggle_user"),
    path("admin/reports/<int:report_id>/review/", views.admin_review_report, name="admin_review_report"),
    path("result/", views.result_view, name="result"),
    path("result/report.pdf", views.analysis_pdf_view, name="analysis_pdf"),
    path("report/", views.report_view, name="report"),
    path("history/", views.history_view, name="history"),
    path("scan-history/", views.scan_history_view, name="scan_history"),
    path("knowledge/", views.knowledge_view, name="knowledge"),
    path("knowledge/<int:id>/", views.knowledge_detail_view, name="knowledge_detail"),
    path("admin/articles/preview/", views.article_preview_view, name="article_preview"),
    path("admin/articles/create/", views.article_create_view, name="article_create"),
    path("admin/articles/<int:pk>/edit/", views.article_edit_view, name="article_edit"),
    path("admin/articles/<int:pk>/delete/", views.article_delete_view, name="article_delete"),
    path("admin/articles/<int:pk>/toggle/", views.article_toggle_status_view, name="article_toggle_status"),
    path("admin/articles/upload-image/", views.article_upload_image_view, name="article_upload_image"),
    path("select-url/", views.select_url_view, name="select_url"),

]
