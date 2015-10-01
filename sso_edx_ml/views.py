from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.shortcuts import redirect


def logout(request, next_page=None,
           redirect_field_name=REDIRECT_FIELD_NAME, *args, **kwargs):
    """
    This view needed for correct redirect to sso-logout page
    """
    if (redirect_field_name in request.POST or
            redirect_field_name in request.GET):
        next_page = request.POST.get(redirect_field_name,
                                     request.GET.get(redirect_field_name))

    if next_page:
        next_page = request.build_absolute_uri(next_page)
    else:
        next_page = request.build_absolute_uri('/')

    return redirect('%s?%s=%s' % (settings.SOCIAL_AUTH_LOGOUT_URL,
                                      redirect_field_name, next_page))
