{{/*

 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

*/}}
{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "superset.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "superset.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "superset.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "client_secret" -}}
{
    "web": {
        "issuer": "https://kc.alboroto.live/auth/realms/alborotoproject",
        "auth_uri": "https://kc.alboroto.live/auth/realms/alborotoproject/protocol/openid-connect/auth",
        "client_id": "superset",
        "client_secret": "64416c72-afbd-4333-a106-bf3d0f26d603",
        "redirect_uris": [
            "https://superset.alboroto.live/*"
        ],
        "userinfo_uri": "https://kc.alboroto.live/auth/realms/alborotoproject/protocol/openid-connect/userinfo",
        "token_uri": "https://kc.alboroto.live/auth/realms/alborotoproject/protocol/openid-connect/token",
        "token_introspection_uri": "https://kc.alboroto.live/auth/realms/alborotoproject/protocol/openid-connect/token/introspect"
    }
}
{{- end -}}

{{- define "keycloak_security_manager" -}}

from flask import redirect, request
from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from urllib.parse import quote
from flask_appbuilder.views import ModelView, SimpleFormView, expose
import logging

class OIDCSecurityManager(SupersetSecurityManager):

    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
        self.authoidview = AuthOIDCView

class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))

            if user is None:
                info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email'])
                user = sm.add_user(info.get('preferred_username'), info.get('given_name'), info.get('family_name'),
                                   info.get('email'), sm.find_role('Gamma'))

            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid

        oidc.logout()
        super(AuthOIDCView, self).logout()
        redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login

        return redirect(
            oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout?redirect_uri=' + quote(redirect_url))
{{- end -}}

{{- define "superset-config" }}
import os
from cachelib.redis import RedisCache

def env(key, default=None):
    return os.getenv(key, default)

MAPBOX_API_KEY = env('MAPBOX_API_KEY', '')
CACHE_CONFIG = {
      'CACHE_TYPE': 'redis',
      'CACHE_DEFAULT_TIMEOUT': 300,
      'CACHE_KEY_PREFIX': 'superset_',
      'CACHE_REDIS_HOST': env('REDIS_HOST'),
      'CACHE_REDIS_PORT': env('REDIS_PORT'),
      'CACHE_REDIS_PASSWORD': env('REDIS_PASSWORD'),
      'CACHE_REDIS_DB': env('REDIS_DB', 1),
}
DATA_CACHE_CONFIG = CACHE_CONFIG
ENABLE_PROXY_FIX = True

SQLALCHEMY_DATABASE_URI = f"postgresql+psycopg2://{env('DB_USER')}:{env('DB_PASS')}@{env('DB_HOST')}:{env('DB_PORT')}/{env('DB_NAME')}"
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = env('SECRET_KEY', 'thisISaSECRET_1234')

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = False
# Add endpoints that need to be exempt from CSRF protection
# WTF_CSRF_EXEMPT_LIST = ['https://kc.alboroto.live']
# A CSRF token that expires in 1 year
# WTF_CSRF_TIME_LIMIT = 60 * 60 * 24 * 365
class CeleryConfig(object):
  BROKER_URL = f"redis://{env('REDIS_HOST')}:{env('REDIS_PORT')}/0"
  CELERY_IMPORTS = ('superset.sql_lab', )
  CELERY_RESULT_BACKEND = f"redis://{env('REDIS_HOST')}:{env('REDIS_PORT')}/0"
  CELERY_ANNOTATIONS = {'tasks.add': {'rate_limit': '10/s'}}

CELERY_CONFIG = CeleryConfig
RESULTS_BACKEND = RedisCache(
      host=env('REDIS_HOST'),
      port=env('REDIS_PORT'),
      key_prefix='superset_results'
)

from keycloak_security_manager import OIDCSecurityManager
from flask_appbuilder.security.manager import AUTH_OID, AUTH_REMOTE_USER, AUTH_DB, AUTH_LDAP, AUTH_OAUTH

import os


'''
---------------------------KEYCLOACK ----------------------------
'''
curr  =  os.path.abspath(os.getcwd())
AUTH_TYPE = AUTH_OID
SECRET_KEY: '64416c72-afbd-4333-a106-bf3d0f26d603'
OIDC_CLIENT_SECRETS =  curr + '/pythonpath/client_secret.json'
OIDC_ID_TOKEN_COOKIE_SECURE = False
OIDC_REQUIRE_VERIFIED_EMAIL = False
OIDC_OPENID_REALM: 'alborotoproject'
OIDC_INTROSPECTION_AUTH_METHOD: 'client_secret_post'
CUSTOM_SECURITY_MANAGER = OIDCSecurityManager
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = 'Gamma'
'''
--------------------------------------------------------------
'''
{{ if .Values.configOverrides }}
# Overrides
{{- range $key, $value := .Values.configOverrides }}
# {{ $key }}
{{ tpl $value $ }}
{{- end }}
{{- end }}

{{- end }}
