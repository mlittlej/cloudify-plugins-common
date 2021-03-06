########
# Copyright (c) 2013 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

MANAGER_FILE_SERVER_URL_KEY = 'MANAGER_FILE_SERVER_URL'
MANAGER_FILE_SERVER_BLUEPRINTS_ROOT_URL_KEY = \
    'MANAGER_FILE_SERVER_BLUEPRINTS_ROOT_URL'
FILE_SERVER_HOST_KEY = 'FILE_SERVER_HOST'
FILE_SERVER_PORT_KEY = 'FILE_SERVER_PORT'
FILE_SERVER_PROTOCOL_KEY = 'FILE_SERVER_PROTOCOL'
REST_HOST_KEY = 'REST_HOST'
MANAGER_FILE_SERVER_DEPLOYMENTS_ROOT_URL_KEY = \
    'MANAGER_FILE_SERVER_DEPLOYMENTS_ROOT_URL'
REST_PORT_KEY = 'REST_PORT'
REST_PROTOCOL_KEY = 'REST_PROTOCOL'
CELERY_BROKER_URL_KEY = 'CELERY_BROKER_URL'
VIRTUALENV_PATH_KEY = 'VIRTUALENV_PATH'
CELERY_WORK_DIR_KEY = 'CELERY_WORK_DIR'
CELERY_WORK_DIR_PATH_KEY = 'CELERY_WORK_DIR_PATH'

AGENT_INSTALL_METHOD_NONE = 'none'
AGENT_INSTALL_METHOD_REMOTE = 'remote'
AGENT_INSTALL_METHOD_INIT_SCRIPT = 'init_script'
AGENT_INSTALL_METHOD_PROVIDED = 'provided'
AGENT_INSTALL_METHODS = [
    AGENT_INSTALL_METHOD_NONE,
    AGENT_INSTALL_METHOD_REMOTE,
    AGENT_INSTALL_METHOD_INIT_SCRIPT,
    AGENT_INSTALL_METHOD_PROVIDED
]
AGENT_INSTALL_METHODS_SCRIPTS = [
    AGENT_INSTALL_METHOD_INIT_SCRIPT,
    AGENT_INSTALL_METHOD_PROVIDED
]

COMPUTE_NODE_TYPE = 'cloudify.nodes.Compute'

BROKER_PORT_NO_SSL = 5672
BROKER_PORT_SSL = 5671
SECURITY_ENABLED_KEY = 'SECURITY_ENABLED'
CLOUDIFY_USERNAME_ENV = 'REST_USERNAME'
CLOUDIFY_PASSWORD_ENV = 'REST_PASSWORD'
CLOUDIFY_AUTHENTICATION_HEADER = 'Authorization'
CLOUDIFY_TOKEN_AUTHENTICATION_HEADER = 'Authentication-Token'
BASIC_AUTH_PREFIX = 'Basic'
VERIFY_REST_CERTIFICATE_KEY = 'VERIFY_REST_CERTIFICATE'
LOCAL_REST_CERT_FILE_KEY = 'LOCAL_REST_CERT_FILE'
REST_CERT_CONTENT_KEY = 'REST_CERT_CONTENT'
CLOUDIFY_SSL_TRUST_ALL = 'CLOUDIFY_SSL_TRUST_ALL'
DEFAULT_REST_PORT = 80
SECURED_REST_PORT = 443
DEFAULT_PROTOCOL = 'http'
CLOUDIFY_TENANT_HEADER = 'Tenant'
SECURED_PROTOCOL = 'https'

AGENT_REST_CERT_PATH = 'AGENT_REST_CERT_PATH'
BROKER_SSL_CERT_PATH = 'BROKER_SSL_CERT_PATH'

BYPASS_MAINTENANCE = 'BYPASS_MAINTENANCE'

LOGGING_CONFIG_FILE = '/etc/cloudify/logging.conf'
