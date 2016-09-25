from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt

from sso_edx_ml import api, views


urlpatterns = [
    url(r'^enrollment_course/$', api.EnrollmentCourse.as_view()),
    url(r'^intercom_settings/$', views.intercom_settings,
        name='intercom-settings'),
    url(r'^access_token/$', csrf_exempt(views.AccessTokenView.as_view()),
        name='access_token'),
]
