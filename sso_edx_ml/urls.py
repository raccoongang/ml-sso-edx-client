from django.conf.urls import url
from sso_edx_ml import api, views


urlpatterns = [
    url(r'^enrollment_course/$', api.EnrollmentCourse.as_view()),
    url(r'^intercom_settings/$', views.intercom_settings),

]
