# ml-sso-edx-client
Python package for support sso in open edx for ml project

# Installation:
```bash
pip install -e git+https://github.com/raccoongang/ml-sso-edx-client.git#egg=ml_sso_edx_client
```

Add in file lms/envs/common.py
```python
INSTALLED_APPS = (
    ...
    'sso_edx_ml',
)
```
