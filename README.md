# ml-sso-edx-client
Python package for support sso in open edx for ml project

# Installation:
```bash
pip install -e git+https://github.com/raccoongang/ml-sso-edx-client.git#egg=ml_sso_edx_client
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
    'ratelimitbackend.backends.RateLimitModelBackend',
)
```

Add middleware classes
```
'sso_edx_ml.middleware.PLPRedirection',
'sso_edx_ml.middleware.SeamlessAuthorization',
```

Add package templates path `/edx/app/edxapp/venvs/edxapp/src/ml-sso-edx-client/sso_edx_ml/templates`
```
TEMPLATE_DIRS = [
    '/edx/app/edxapp/venvs/edxapp/src/ml-sso-edx-client/sso_edx_ml/templates',
    PROJECT_ROOT / "templates",
    ...
]

MAKO_TEMPLATES['main'] = [
                          '/edx/app/edxapp/venvs/edxapp/src/ml-sso-edx-client/sso_edx_ml/templates',
                          PROJECT_ROOT / 'templates',
                          ...
                          ]
```

Open `lms.env.json` and add
```
"THIRD_PARTY_AUTH_BACKENDS": "sso_edx_ml.backends.ml.MLBackend"
```