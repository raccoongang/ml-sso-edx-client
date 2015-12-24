import re
from django.conf import settings
from django.contrib.auth.models import User
from requests import HTTPError
from social.exceptions import AuthFailed
from social.strategies.utils import get_current_strategy
from social.utils import handle_http_errors
from social.backends.oauth import BaseOAuth2

from enrollment.data import create_course_enrollment
from student.forms import AccountCreationForm
from student.models import CourseEnrollment


DEFAULT_AUTH_PIPELINE = (
    'third_party_auth.pipeline.parse_query_params',
    'social.pipeline.social_auth.social_details',
    'social.pipeline.social_auth.social_uid',
    'social.pipeline.social_auth.auth_allowed',
    'social.pipeline.social_auth.social_user',
    'third_party_auth.pipeline.associate_by_email_if_login_api',
    'social.pipeline.user.get_username',
    'third_party_auth.pipeline.set_pipeline_timeout',
    'sso_edx_ml.pipeline.ensure_user_information',
    'social.pipeline.user.create_user',
    'social.pipeline.social_auth.associate_user',
    'social.pipeline.social_auth.load_extra_data',
    'social.pipeline.user.user_details',
    'third_party_auth.pipeline.set_logged_in_cookies',
    'third_party_auth.pipeline.login_analytics',
)


class MLBackend(BaseOAuth2):

    name = 'sso_ml-oauth2'
    ID_KEY = 'username'
    AUTHORIZATION_URL = '{}/OAuth2/Authorize'.format(settings.SSO_ML_URL)
    ACCESS_TOKEN_URL = '{}/oauth2/token'.format(settings.SSO_ML_URL)
    REDIRECT_URI = 'https://lms.millionlights.org/auth/complete/sso_ml-oauth2/'
    DEFAULT_SCOPE = []
    REDIRECT_STATE = False
    ACCESS_TOKEN_METHOD = 'POST'

    PIPELINE = DEFAULT_AUTH_PIPELINE
    skip_email_verification = True

    def auth_url(self):
        return '{}&auth_entry={}'.format(
            super(MLBackend, self).auth_url(),
            self.data.get('auth_entry', 'login')
        )

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""
        self.strategy.session.setdefault('{}_state'.format(self.name),
                                         self.data.get('state'))
        self.strategy.session.setdefault('next', '/dashboard')
        return super(MLBackend, self).auth_complete(*args, **kwargs)

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        self.strategy.session.setdefault('auth_entry', 'register')
        return super(MLBackend, self).pipeline(
            pipeline=self.PIPELINE, pipeline_index=pipeline_index, *args, **kwargs
        )

    def get_user_details(self, response):
        """ Return user details from MIPT account. """
        return response

    def get_redirect_uri(self, state=None):
        return self.REDIRECT_URI

    def user_data(self, access_token, *args, **kwargs):
        """ Grab user profile information from MIPT. """
        return self.get_json(
            '{}/api/me'.format(settings.SSO_ML_API_URL),
            params={'access_token': access_token},
            headers={'Authorization': 'Bearer {}'.format(access_token)}
        )

    def do_auth(self, access_token, *args, **kwargs):
        """Finish the auth process once the access_token was retrieved"""
        data = self.user_data(access_token)
        data['access_token'] = access_token
        kwargs.update(data)
        kwargs.update({'response': data, 'backend': self})
        pipeline = self.strategy.authenticate(*args, **kwargs)
        try:
            username = User.objects.get(email=data["Email"]).username
            self.enroll_user(username, access_token)
        except User.DoesNotExist:
            pass
        return pipeline

    def enroll_user(self, username, access_token):
        if access_token:
            try:
                CourseEnrollment.objects.filter(user__username=username).delete()
                user_courses = self.get_json(
                    '{}/api/MyCourses'.format(settings.SSO_ML_API_URL),
                    headers={'Authorization': 'Bearer {}'.format(access_token)}
                )
                if len(user_courses):
                    for course in user_courses:
                        try:
                            create_course_enrollment(
                                username,
                                course["CourseLMSId"],
                                mode='honor',
                                is_active=True
                            )
                        except:
                            pass
            except Exception as ex:
                raise Exception("Failed to fetch courses from Millionlights server. %s" % str(ex))
        else:
            raise Exception("Access token is required")
            
    def request(self, url, method='GET', *args, **kwargs):
        kwargs['verify'] = False
        return super(MLBackend, self).request(url, method=method, *args, **kwargs)

    def authenticate(self, *args, **kwargs):
        if 'username' in kwargs and 'password' in kwargs and self.strategy is None:
            self.strategy = get_current_strategy()
            if self.strategy:
                try:
                    return self.ml_authenticate(kwargs['username'], kwargs['password'])
                except (AuthFailed, HTTPError):
                    return None
        else:
            return super(MLBackend, self).authenticate(*args, **kwargs)

    def ml_authenticate(self, username, password):
        response = self.get_json(url=self.access_token_url(),
                                 method=self.ACCESS_TOKEN_METHOD,
                                 data=self.get_data(username, password),
                                 headers=self.auth_headers())
        self.process_error(response)
        if 'access_token' in response:
            try:
                user = User.objects.get(email=username)
                return  user
            except User.DoesNotExist:
                return self.create_user(response['access_token'])

    def get_data(self, username, password):
        client_id, client_secret = self.get_key_and_secret()
        return {
            'grant_type': 'password',
            'client_id': client_id,
            'client_secret': client_secret,
            'username': username,
            'password': password
        }

    def create_user(self, access_token):
        from student.views import _do_create_account

        data = self.user_data(access_token)
        data = self.change_user_data(data)

        try:
            user = User.objects.get(email=data["email"])
        except User.DoesNotExist:
            form = AccountCreationForm(
                data=data,
                extra_fields={},
                extended_profile_fields={},
                enforce_username_neq_password=False,
                enforce_password_policy=False,
                tos_required=False,
            )
            (user, profile, registration) = _do_create_account(form)
            user.first_name = data['firstname']
            user.last_name = data['lastname']
            user.is_active = True
            user.set_unusable_password()
            user.save()

        self.enroll_user(user.username, access_token)
        return user

    def change_user_data(self, data):
        from third_party_auth.pipeline import make_random_password

        firstname = data.get('Firstname', '')
        lastname = data.get('Lastname', '')
        email =  data.get('Email', '')
        username = re.sub('[\W_]', '', email)
        name = ' '.join([firstname, lastname]).strip() or username
        return {
            'email': email,
            'firstname': firstname,
            'lastname': lastname,
            'username': username,
            'name': name,
            'password': make_random_password()
        }


class MLBackendCMS(MLBackend):

    name = 'sso_ml_cms-oauth2'
