########
# Copyright (c) 2017 GigaSpaces Technologies Ltd. All rights reserved
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

import os
import copy
import ghost
from cryptography.fernet import InvalidToken

from .. import ctx
from ..exceptions import NonRecoverableError

PASSPHRASE_FILENAME = 'passphrase.ghost'
GHOST_HOME = os.path.join(os.path.expanduser('~'), '.ghost')
DEFAULT_GHOST_STASH = os.path.join(GHOST_HOME, 'stash.json')
POTENTIAL_PASSPHRASE_LOCATIONS = [
    os.path.abspath(PASSPHRASE_FILENAME),
    os.path.join(GHOST_HOME, PASSPHRASE_FILENAME),
]
DEFAULT_STORAGE_MAPPING = 'tinydb'
CONTR_CFG = 'controller_config'
DEFAULT_SECRET_SCHEMAS = {
    'openstack_config': {
        'key_name': 'openstack',
        'database_uri': '~/.ghost/stash.json',
        'storage_mapping': 'tinydb',
        'secret_names': {
            'username': '',
            'password': '',
            'tenant_name': ''
        }
    },
    'aws_config': {
        'key_name': 'aws',
        'database_uri': '~/.ghost/stash.json',
        'storage_mapping': 'tinydb',
        'secret_names': {
            'aws_access_key_id': '',
            'aws_secret_access_key': ''
        }
    },
    'azure_config': {
        'key_name': 'azure',
        'database_uri': '~/.ghost/stash.json',
        'storage_mapping': 'tinydb',
        'secret_names': {
            'subscription_id': '',
            'tenant_id': '',
            'client_id': '',
            'client_secret': ''
        }
    }
}


class CloudifySecretStore():

    def __init__(self,
                 passphrase=None,
                 database_uri=DEFAULT_GHOST_STASH,
                 storage_mapping=DEFAULT_STORAGE_MAPPING):
        self.passphrase = self._get_secret_store_passphrase(passphrase)
        self.storage = self._get_secret_store_storage(database_uri, storage_mapping)
        self.use = \
            False if not self.controller_config.get('use_secret_store') else True

    @property
    def controller_config(self):
        return self._get_controller_config()

    @staticmethod
    def _get_controller_config(controller_config=None):

        if controller_config:
            return controller_config
        if 'node-instance' not in ctx.type:
            if CONTR_CFG in ctx.source.instance.runtime_properties.keys():
                return ctx.source.instance.runtime_properties[CONTR_CFG]
            elif CONTR_CFG in ctx.source.node.properties.keys():
                return ctx.source.node.properties[CONTR_CFG]
        else:
            if CONTR_CFG in ctx.instance.runtime_properties.keys():
                return ctx.instance.runtime_properties[CONTR_CFG]
            elif CONTR_CFG in ctx.node.properties.keys():
                return ctx.node.properties[CONTR_CFG]

        ctx.logger.warn(
            'No controller_config was provided. '
            'Currently this is OK, because the controller_config '
            'is not fully supported in Cloudify.'
        )

        return {}

    def _get_secret_store_passphrase(self, passphrase):
        # Copied from ghost master because it's not in 0.3.0
        if not passphrase:
            for passphrase_file_path in POTENTIAL_PASSPHRASE_LOCATIONS:
                if os.path.isfile(passphrase_file_path):
                    with open(passphrase_file_path) as passphrase_file:
                        passphrase = passphrase_file.read()
        return passphrase

    def _get_secret_store_storage(self, database_uri, storage_mapping):
        backend = ghost.STORAGE_MAPPING.get(storage_mapping)
        try:
            storage = backend(db_path=database_uri)
        except (ghost.GhostError, ImportError):
            raise NonRecoverableError(
                'No valid storage path provided.')
        return storage

    def get_stash(self, storage=None, passphrase=None):
        passphrase = passphrase or self.passphrase
        storage = storage or self.storage
        return ghost.Stash(storage, passphrase=passphrase)

    def get_key(self, key_name, stash=None):
        stash = stash or self.get_stash()
        try:
            key = stash.get(key_name=key_name)
        except InvalidToken as e:
            raise NonRecoverableError(
                'The ghost passphrase is wrong. '
                'Make sure you do not add any extraneous characters '
                'to the passphrase file. '
                'Error: {0}'.format(str(e)))
        except IOError as e:
            raise NonRecoverableError(
                'Unable to get secret: {0}'.format(str(e)))
        return key

    def get_secret(self, key_name, secret_name, stash=None):
        key = self.get_key(key_name, stash)
        try:
            return key.get('value', {}).get(secret_name)
        except AttributeError:
            ctx.logger.warn(
                'key {0} does not contain secret {1}.'
                    .format(key_name, secret_name)
            )

    def update_config_with_secrets(self, config, config_schema_name=None):
        ''' Create a config based on 'config_schema_name'.
        Every cloudify node has the "controller_config" property.
        Nested in this property is another property called "secret_schemas".
        The "secret_schemas" are schemas that can be used here.
        This function takes a schema from the controller_config by name
        and fills out its values based on the schema key names.

        Example:
          example_node:
            type: cloudify.aws.nodes.Instance
            properties:
              controller_config:
                secret_schemas:
                  aws_config:
                    key_name: 'aws_config'
                    database_uri: none
                    secret_names:
                      aws_access_key_id: ''
                      aws_secret_access_key: ''

          This function will get the key named "aws_config" from the secret store.
          It will then fill out the values for 'aws_access_key_id', etc and return it as a dictionary.


        :param config_schema_name:
        :return:
        '''

        ctx.logger.info('CONFIG {0}'.format(config))

        secret_config_schema = copy.deepcopy(
            self.controller_config.get(
                'secret_schemas', DEFAULT_SECRET_SCHEMAS).get(
                config_schema_name, {}))

        storage_mapping = secret_config_schema.get('storage_mapping',
                                                   DEFAULT_STORAGE_MAPPING)
        database_uri = secret_config_schema.get('database_uri',
                                                DEFAULT_GHOST_STASH)

        if storage_mapping != DEFAULT_STORAGE_MAPPING or \
                        database_uri != DEFAULT_GHOST_STASH:
            self.storage = self._get_secret_store_storage(
                database_uri=database_uri,
                storage_mapping=storage_mapping)

        try:
            stash = self.get_stash()
        except:
            ctx.logger.warn(
                'No stash exists.')
            stash = None

        if stash and secret_config_schema:
            ctx.logger.info('secret_config_schema: {0}'.format(secret_config_schema))
            try:
                secret_key_name = secret_config_schema.pop('key_name')
            except KeyError:
                raise NonRecoverableError(
                    'The secret_schema {0} is not properly formatted. '
                    'No key_name is provided.'
                        .format(config_schema_name)
                )

            secret_schema = secret_config_schema.get('secret_names')
            for secret_name in secret_schema.keys():
                if secret_name:
                    secret = self.get_secret(key_name=secret_key_name,
                                             secret_name=secret_name,
                                             stash=stash)
                    config.update({secret_name: secret})

        ctx.logger.info('CONFIG {0}'.format(config))

        return config
