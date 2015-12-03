from django.conf.urls import url
from sso_edx_ml import api


urlpatterns = [
    url(r'^enrollment_course/$', api.EnrollmentCourse.as_view()),

]
