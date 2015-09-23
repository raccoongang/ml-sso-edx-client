import string  # pylint: disable-msg=deprecated-module
import json
import logging

from django.http import HttpResponseBadRequest, HttpResponse
from django.contrib.auth.models import User

from social.pipeline import partial

from student.views import create_account_with_params, reactivation_email_for_user
from student.models import UserProfile, CourseAccessRole
from student.roles import (
    CourseInstructorRole, CourseStaffRole, GlobalStaff, OrgStaffRole,
    UserBasedRole, CourseCreatorRole, CourseBetaTesterRole, OrgInstructorRole,
    LibraryUserRole, OrgLibraryUserRole
)
from third_party_auth.pipeline import (
    make_random_password, NotActivatedException, AuthEntryError
)
from opaque_keys.edx.keys import CourseKey

log = logging.getLogger(__name__)

# The following are various possible values for the AUTH_ENTRY_KEY.
AUTH_ENTRY_LOGIN = 'login'
AUTH_ENTRY_REGISTER = 'register'
AUTH_ENTRY_ACCOUNT_SETTINGS = 'account_settings'

AUTH_ENTRY_LOGIN_2 = 'account_login'
AUTH_ENTRY_REGISTER_2 = 'account_register'

# Entry modes into the authentication process by a remote API call (as opposed to a browser session).
AUTH_ENTRY_LOGIN_API = 'login_api'
AUTH_ENTRY_REGISTER_API = 'register_api'


def is_api(auth_entry):
    """Returns whether the auth entry point is via an API call."""
    return (auth_entry == AUTH_ENTRY_LOGIN_API) or (auth_entry == AUTH_ENTRY_REGISTER_API)


def set_roles_for_edx_users(user, permissions, strategy):
    '''
    This function is specific functional for open-edx platform.
    It create roles for edx users from sso permissions.
    '''

    log_message = 'For User: {}, object_type {} and object_id {} there is not matched Role for Permission set: {}'

    global_perm = {'Read', 'Update', 'Delete', 'Publication', 'Enroll', 'Manage(permissions)'}
    staff_perm = {'Read', 'Update', 'Delete', 'Publication', 'Enroll'}
    tester_perm = {'Read', 'Enroll'}

    role_ids = set(user.courseaccessrole_set.values_list('id', flat=True))
    new_role_ids = []

    is_global_staff = False
    for role in permissions:
        _log = False
        if role['obj_type'] == '*':
            if '*' in role['obj_perm'] or global_perm.issubset(set(role['obj_perm'])):
                GlobalStaff().add_users(user)
                is_global_staff = True

            elif 'Create' in role['obj_perm']:
                if not CourseCreatorRole().has_user(user):
                    CourseCreatorRole().add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=CourseCreatorRole.ROLE)
                new_role_ids.append(car.id)

            if role['obj_perm'] != '*' and global_perm != set(role['obj_perm']) and ['Create'] != role['obj_perm']:
                _log = True

        elif role['obj_type'] == 'edxorg':
            if '*' in role['obj_perm'] or global_perm.issubset(set(role['obj_perm'])):
                if not OrgInstructorRole(role['obj_id']).has_user(user):
                    OrgInstructorRole(role['obj_id']).add_users(user)
                car = CourseAccessRole.objects.get(user=user,
                                                   role=OrgInstructorRole(role['obj_id'])._role_name,
                                                   org=role['obj_id'])
                new_role_ids.append(car.id)

            elif staff_perm.issubset(set(role['obj_perm'])):
                if not OrgStaffRole(role['obj_id']).has_user(user):
                    OrgStaffRole(role['obj_id']).add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=OrgStaffRole(role['obj_id'])._role_name,
                                                   org=role['obj_id'])
                new_role_ids.append(car.id)

            elif 'Read' in role['obj_perm']:
                if not OrgLibraryUserRole(role['obj_id']).has_user(user):
                    OrgLibraryUserRole(role['obj_id']).add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=OrgLibraryUserRole.ROLE, org=role['obj_id'])
                new_role_ids.append(car.id)

            if role['obj_perm'] != '*' and global_perm != set(role['obj_perm']) and \
                    staff_perm != set(role['obj_perm']) and 'Read' not in role['obj_perm']:
                _log = True

        elif role['obj_type'] in ['edxcourse', 'edxlibrary']:

            course_key = CourseKey.from_string(role['obj_id'])

            if '*' in role['obj_perm'] or global_perm.issubset(set(role['obj_perm'])):
                if not CourseInstructorRole(course_key).has_user(user):
                    CourseInstructorRole(course_key).add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=CourseInstructorRole.ROLE, course_id=course_key)
                new_role_ids.append(car.id)

            elif staff_perm.issubset(set(role['obj_perm'])):
                if not CourseStaffRole(course_key).has_user(user):
                    CourseStaffRole(course_key).add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=CourseStaffRole.ROLE, course_id=course_key)
                new_role_ids.append(car.id)

            elif tester_perm.issubset(set(role['obj_perm'])):
                if not CourseBetaTesterRole(course_key).has_user(user):
                    CourseBetaTesterRole(course_key).add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=CourseBetaTesterRole.ROLE, course_id=course_key)
                new_role_ids.append(car.id)

            elif role['obj_type'] == 'edxlibrary' and 'Read' in role['obj_perm']:
                if not LibraryUserRole(course_key).has_user(user):
                    LibraryUserRole(course_key).add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=CourseBetaTesterRole.ROLE, course_id=course_key)
                new_role_ids.append(car.id)

            if role['obj_perm'] != '*' and global_perm != set(role['obj_perm']) and \
                staff_perm != set(role['obj_perm']) and tester_perm != set(role['obj_perm']) and 'Read' not in role['obj_perm']:
                _log = True

        elif role['obj_type'] == 'edxcourserun':

            course_key = CourseKey.from_string(role['obj_id'])

            if '*' in role['obj_perm'] or global_perm.issubset(set(role['obj_perm'])):
                if not CourseInstructorRole(course_key).has_user(user):
                    CourseInstructorRole(course_key).add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=CourseInstructorRole.ROLE, course_id=course_key)
                new_role_ids.append(car.id)
            elif staff_perm.issubset(set(role['obj_perm'])):
                if not CourseStaffRole(course_key).has_user(user):
                    CourseStaffRole(course_key).add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=CourseStaffRole.ROLE, course_id=course_key)
                new_role_ids.append(car.id)
            elif tester_perm.issubset(set(role['obj_perm'])):
                if not CourseBetaTesterRole(course_key).has_user(user):
                    CourseBetaTesterRole(course_key).add_users(user)
                car = CourseAccessRole.objects.get(user=user, role=CourseBetaTesterRole.ROLE, course_id=course_key)
                new_role_ids.append(car.id)

            if role['obj_perm'] != '*' and global_perm != set(role['obj_perm']) and \
                staff_perm != set(role['obj_perm']) and tester_perm != set(role['obj_perm']):
                _log = True

        if _log:
            logging.warning(log_message.format(user.id, role['obj_type'], role['obj_id'], str(role['obj_perm'])))

    if (not is_global_staff) and GlobalStaff().has_user(user):
        GlobalStaff().remove_users(user)

    remove_roles = role_ids - set(new_role_ids)

    if remove_roles:
        entries = CourseAccessRole.objects.filter(id__in=list(remove_roles))
        entries.delete()


AUTH_DISPATCH_URLS = {
    AUTH_ENTRY_LOGIN: '/login',
    AUTH_ENTRY_REGISTER: '/register',
    AUTH_ENTRY_ACCOUNT_SETTINGS: '/account/settings',

    # This is left-over from an A/B test
    # of the new combined login/registration page (ECOM-369)
    # We need to keep both the old and new entry points
    # until every session from before the test ended has expired.
    AUTH_ENTRY_LOGIN_2: '/account/login/',
    AUTH_ENTRY_REGISTER_2: '/account/register/',

}

_AUTH_ENTRY_CHOICES = frozenset([
    AUTH_ENTRY_LOGIN,
    AUTH_ENTRY_REGISTER,
    AUTH_ENTRY_ACCOUNT_SETTINGS,

    AUTH_ENTRY_LOGIN_2,
    AUTH_ENTRY_REGISTER_2,

    AUTH_ENTRY_LOGIN_API,
    AUTH_ENTRY_REGISTER_API,
])

_DEFAULT_RANDOM_PASSWORD_LENGTH = 12
_PASSWORD_CHARSET = string.letters + string.digits

class JsonResponse(HttpResponse):
    def __init__(self, data=None):
        super(JsonResponse, self).__init__(
            json.dumps(data), mimetype='application/json; charset=utf-8'
        )


@partial.partial
def ensure_user_information(
    strategy, auth_entry, backend=None, user=None, social=None,
    allow_inactive_user=False, *args, **kwargs):
    """
    Ensure that we have the necessary information about a user (either an
    existing account or registration data) to proceed with the pipeline.
    """

    response = {}
    data = kwargs['response']

    try:
        data['email'] = data.pop('Email')
    except KeyError:
        raise Exception("Email field is required")
    data['username'] = data['email'].split("@")[0].replace(".", "")\
        .replace("_", "").replace(" ", "")

    def dispatch_to_register():
        """Force user creation on login or register"""

        request = strategy.request
        data['terms_of_service'] = True
        data['honor_code'] = True
        data['password'] = make_random_password()
        # force name creation if it is empty in sso-profile
        data['name'] = ' '.join([data.get('Firstname', ''),
                                 data.get('Lastname', '')]).strip()
        data['provider'] = backend.name

        if request.session.get('ExternalAuthMap'):
            del request.session['ExternalAuthMap']

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            create_account_with_params(request, data)
            user = request.user
            user.is_active = True
            user.save()

        return {'user': user}

    if not user:
        if auth_entry in [AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API]:
            return HttpResponseBadRequest()
        elif auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_LOGIN_2]:
            response = dispatch_to_register()
        elif auth_entry in [AUTH_ENTRY_REGISTER, AUTH_ENTRY_REGISTER_2]:
            response = dispatch_to_register()
        elif auth_entry == AUTH_ENTRY_ACCOUNT_SETTINGS:
            raise AuthEntryError(
                backend, 'auth_entry is wrong. Settings requires a user.')
        else:
            raise AuthEntryError(backend, 'auth_entry invalid')
    else:
        user.username = data['username']
        user.first_name = data['firstname']
        user.last_name = data['lastname']
        user.save()

        try:
            user_profile = UserProfile.objects.get(user=user)
        except User.DoesNotExist:
            user_profile = None
        except User.MultipleObjectsReturned:
            user_profile = UserProfile.objects.filter(user=user)[0]

        if user_profile:
            user_profile.name = ' '.join(
                [data['firstname'], data['lastname']]
            ).strip() or data['username']

    user = user or response.get('user')
    if user and not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            reactivation_email_for_user(user)
            raise NotActivatedException(backend, user.email)

    # add roles for User
    permissions = kwargs.get('response', {}).get('permissions')
    if permissions is not None:
        try:
            set_roles_for_edx_users(user, permissions, strategy)
        except Exception as e:
            log.error(u'set_roles_for_edx_users error: {}'.format(e))

    return response
