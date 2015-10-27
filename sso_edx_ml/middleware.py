import re
import requests

from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME, logout
from django.shortcuts import redirect

from social.apps.django_app.views import auth, NAMESPACE

from student.models import CourseEnrollment
from opaque_keys.edx.keys import CourseKey


class SeamlessAuthorization(object):
    cookie_name = 'MillionlightsSSO'

    def process_request(self, request):
        """
        Check multidomain cookie and if user is authenticated on sso, login it on edx
        """
        backend = settings.SSO_ML_BACKEND_NAME
        current_url = request.get_full_path()

        # don't work for admin
        if hasattr(settings, 'SOCIAL_AUTH_EXCLUDE_URL_PATTERN'):
            r = re.compile(settings.SOCIAL_AUTH_EXCLUDE_URL_PATTERN)
            if r.match(current_url):
                return None

        auth_cookie = request.COOKIES.get(self.cookie_name)
        auth_cookie_portal = request.session.get(self.cookie_name)
        continue_url = reverse('{0}:complete'.format(NAMESPACE),
                               args=(backend,))
        is_auth = request.user.is_authenticated()
        is_same_user = (auth_cookie == auth_cookie_portal)

        # Check for infinity redirection loop
        is_continue = (continue_url in current_url)

        request.session[self.cookie_name] = auth_cookie
        if (auth_cookie and not is_continue and (not is_auth or not is_same_user)) or \
            ('force_auth' in request.session and request.session.pop('force_auth')):
            query_dict = request.GET.copy()
            query_dict[REDIRECT_FIELD_NAME] = current_url
            query_dict['auth_entry'] = 'login'
            request.GET = query_dict
            logout(request)
            return auth(request, backend)
        elif not auth_cookie and is_auth:
            # Logout if user isn't logined on sso
            logout(request)


class PortalRedirection(object):

    def process_request(self, request):
        """
        Redirect to Portal for pages that have duplicated functionality on Portal
        """

        current_url = request.get_full_path()
        if current_url:
            start_url = current_url.split('/')[1]
        else:
            start_url = ''

        auth_process_urls = ('oauth2', 'auth', 'login_oauth_token', 'social-logout')
        api_urls = ('api', 'user_api', 'notifier_api')

        handle_local_urls = ('i18n', 'search', 'verify_student', 'certificates', 'jsi18n',
                            'course_modes',  '404', '500', 'wiki', 'notify', 'courses', 'xblock',
                            'change_setting', 'account', 'notification_prefs', 'admin', 'survey',
                            'dashboard')
        handle_local_urls += auth_process_urls + api_urls

        if settings.DEBUG:
            debug_handle_local_urls = ('debug', settings.STATIC_URL, settings.MEDIA_URL)
            handle_local_urls += debug_handle_local_urls

        is_courses_list_or_about_page = False
        r = re.compile(r'^/courses/%s/about' % settings.COURSE_ID_PATTERN)
        rr = re.compile(r'^/courses/%s' % settings.COURSE_ID_PATTERN)
        m = rr.match(current_url)
        if r.match(current_url):
            is_courses_list_or_about_page = True

        if request.path == "/courses/" or request.path == "/courses":
            is_courses_list_or_about_page = True

        if start_url not in handle_local_urls or is_courses_list_or_about_page:
            # return redirect("%s%s" % (settings.PORTAL_URL, current_url))
            return redirect("%s%s" % (settings.PORTAL_URL, ''))

        is_auth = request.user.is_authenticated()
        if not is_auth and start_url not in auth_process_urls and \
                start_url not in api_urls:
            request.session['force_auth'] = True

        if is_auth and request.user and m:
            course_key = m.group(1)
            enrolled_students = CourseEnrollment.objects.users_enrolled_in(CourseKey.from_string(course_key))\
                .filter(username=request.user.username)

            if not enrolled_students:
                try:
                    response = requests.get(
                        "{}/api/GetCourseDetails".format(settings.SSO_ML_API_URL), 
                        params={"lmsCourseId": course_key}, 
                        verify=False
                    ).json()
                    ml_id = response[0]["MLCourseId"]
                    return redirect("%s%s" % (settings.PORTAL_URL, '/Course/AboutCourse?id=%s&type=&pe=0' % ml_id))
                except:
                    return redirect("%s%s" % (settings.PORTAL_URL, '/Course/AllCourses'))
