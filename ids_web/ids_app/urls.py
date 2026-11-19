from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views  # ✅ Import all views at once
from .views import signup_view, public_login

urlpatterns = [
    path('', views.home, name='home'),  # Homepage
    path('dashboard/', views.dashboard, name='dashboard'),  # Dashboard Page
    path('index/', views.index, name='index'),  # System Analytics Page
    path('live_attack_data/', views.live_attack_data, name='live_attack_data'),  # Real-time attack data
    path('ids_detection/', views.ids_detection, name='ids_detection'),  # IDS Detection Page
    path('grnn/', views.grnn_analysis, name='grnn_analysis'),  # GrNN Granular Analysis
    path('grnn/detect/', views.grnn_detect, name='grnn_detect'),  # GrNN Detection API
    path("signup/", signup_view, name="signup"),
    path("login/", public_login, name="public_login"),
]

# ✅ Serve media files in development mode
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)




