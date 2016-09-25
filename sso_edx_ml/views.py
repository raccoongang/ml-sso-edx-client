import json

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import HttpResponse
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


def intercom_settings(request):
    if request.is_ajax():
        return HttpResponse(json.dumps({'api_id': settings.SSO_ML_INTERCOM_API_ID}),
                            content_type='application/json')


from django.contrib.auth import authenticate
from django.contrib.auth.models import User

from provider.forms import OAuthValidationError
from provider.oauth2.views import OAuthError
from oauth2_provider.views import AccessTokenView as AccessTokenProviderView


class PasswordGrantForm(provider.oauth2.forms.PasswordGrantForm):

    def clean(self):
        data = self.cleaned_data
        username = data.get('username')
        password = data.get('password')
        token = data.get('token')

        if token:
            user = authenticate(token=token)
        else:
            user = authenticate(username=username, password=password)

        if user is None:
            try:
                user_obj = User.objects.get(email=username)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                user = None

        if user is None:
            raise OAuthValidationError({'error': 'invalid_grant'})

        data['user'] = user
        return data


class AccessTokenView(AccessTokenProviderView):

    def get_password_grant(self, _request, data, client):
        form = PasswordGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data
