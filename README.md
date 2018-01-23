# ml-sso-edx-client
Python package for support sso in open edx for ml project

# Installation:
```bash
pip install -e git+https://github.com/raccoongang/ml-sso-edx-client.git@ml-ficus#egg=ml_sso_edx_client
```

Add in file lms/envs/common.py. It's preffered to place it somewhere at the top of the list
```python
INSTALLED_APPS = (
    ...
    'sso_edx_ml',
    ...
)
```

Add `sso_edx_ml.backends.ml.MLBackend` to AUTHENTICATION_BACKENDS
```
AUTHENTICATION_BACKENDS = (
    'sso_edx_ml.backends.ml.MLBackend',
)
```

Add middleware classes
```
'sso_edx_ml.middleware.SeamlessAuthorization',
'sso_edx_ml.middleware.PortalRedirection',
```

Also add
```
# SSO
PORTAL_URL = 'https://www.millionlights.org'
SSO_ML_URL = PORTAL_URL
SSO_ML_BACKEND_NAME = 'sso_ml-oauth2'
SSO_ML_API_URL = PORTAL_URL
SOCIAL_AUTH_ALWAYS_ASSOCIATE = True
SOCIAL_AUTH_LOGOUT_URL = "{}/{}".format(PORTAL_URL, 'UserRegister/LoginOut')
SOCIAL_AUTH_EXCLUDE_URL_PATTERN = r'^/admin'

THIRD_PARTY_AUTH_BACKENDS = ('sso_edx_ml.backends.ml.MLBackend',)
```

# IF YOU USING BRANCH "millionlights-ficus" FROM https://github.com/raccoongang/edx-platform, JUST ADD THIS:

```
"ADDL_MIDDLEWARE_CLASSES": ["sso_edx_ml.middleware.SeamlessAuthorization", "sso_edx_ml.middleware.PortalRedirection"],
"THIRD_PARTY_AUTH_BACKENDS": ["sso_edx_ml.backends.ml.MLBackend"],
"ADDL_INSTALLED_APPS": ["sso_edx_ml"],
"SSO_ML_BACKEND_NAME": "sso_ml-oauth2",
```
'''to file /edx/app/edxapp/lms.env.json'''
