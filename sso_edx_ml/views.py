import json

from django.contrib.auth import authenticate, REDIRECT_FIELD_NAME
from django.contrib.auth.models import User
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import redirect
from django import forms

import provider.oauth2.forms
import provider.constants

from provider.forms import OAuthValidationError
from provider.oauth2.views import OAuthError
from oauth2_provider.views import AccessTokenView as AccessTokenProviderView
from provider.oauth2.models import Client

import logging
log = logging.getLogger(__name__)


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

    return redirect('%s?%s=%s' % (
        settings.SOCIAL_AUTH_LOGOUT_URL, redirect_field_name, next_page)
    )


def intercom_settings(request):
    if request.is_ajax():
        return HttpResponse(
            json.dumps({'api_id': settings.SSO_ML_INTERCOM_API_ID}),
            content_type='application/json'
        )


class PasswordGrantForm(provider.oauth2.forms.PasswordGrantForm):

    token = forms.CharField(required=False)

    def clean_username(self):
        username = self.cleaned_data.get('username', '')
        return username

    def clean_password(self):
        password = self.cleaned_data.get('password', '')
        return password

    def clean(self):
        data = self.cleaned_data
        username = data.get('username')
        password = data.get('password')
        token = self.data.get('Token')
        if token:
            user = authenticate(token=token, username='')
        else:
            user = authenticate(username=username, password=password)

            if user is None:
                try:
                    user_obj = User.objects.get(email=username)
                    user = authenticate(
                        username=user_obj.username, password=password
                    )
                except User.DoesNotExist:
                    user = None

        if user is None:
            raise OAuthValidationError({'error': 'invalid_grant'})

        data['user'] = user
        data.setdefault('client_id', self.data.get('client_id', ''))
        return data


class PublicPasswordGrantForm(PasswordGrantForm):
    """
    Form wrapper to ensure the the customized PasswordGrantForm is used
    during client authentication.
    """

    def clean(self):
        data = super(PublicPasswordGrantForm, self).clean()

        try:
            client = Client.objects.get(client_id=data.get('client_id'))
        except Client.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_client'})

        if client.client_type != provider.constants.PUBLIC:
            raise OAuthValidationError({'error': 'invalid_client'})

        data['client'] = client
        return data


class PublicPasswordBackend(object):
    """
    Simple client authentication wrapper backends that delegates to
    `oauth2_provider.forms.PublicPasswordGrantForm`
    """

    def authenticate(self, request=None):
        """
        Returns client if correctly authenticated. Otherwise returns None
        """

        if request is None:
            return None

        form = PublicPasswordGrantForm(request.REQUEST)
        # pylint: disable=no-member
        if form.is_valid():
            return form.cleaned_data.get('client')

        return None


class AccessTokenView(AccessTokenProviderView):

    authentication = (PublicPasswordBackend, )

    def get_password_grant(self, _request, data, client):
        form = PasswordGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data
