from pydantic import BaseModel
import typing as t
import datetime
from dateutil import parser
from pykeepass.entry import Entry as KeePassEntry
import logging

import re


extract_key_from_path = re.compile('.*/([^/]+)$')


keepass_default_fields = [ 'username', 'password', 'notes' ]

class HashiCorpVaultSecret(BaseModel):
    data: dict
    metadata: dict

class SyncKeyModel(BaseModel):
    name: str = 'Unnamed'
    exists_in_vault: bool = False
    exists_in_keepass: bool = False
    full_path: str
    last_modification_time: int = 0
    data: dict = dict()


    def __eq__(self, obj_compare: 'SyncKeyModel'):
        
        equals: bool = False

        equals = self.name == obj_compare.name \
            and self.full_path == obj_compare.full_path

        if equals:
            for key, value in self.data.items():
                if obj_compare.data[key] != value:
                    equals = False
                    break

        return equals
            
    @classmethod
    def from_keepass(class_name, entry: KeePassEntry) -> 'SyncKeyModel':
        self = SyncKeyModel(full_path=  '/' + '/'.join(entry.path))
        self.exists_in_keepass = True
        self.name = entry.title

        for field_name in  keepass_default_fields:
            logging.debug('extracting key %s from keypass file ...', field_name)
            self.data[field_name] = getattr( entry, field_name)

        for key, value in entry.custom_properties.items():
            logging.debug('extracting custom key %s from keypass file ...', key)
            self.data[key] = value


        self.last_modification_time = entry.mtime.timestamp()
        return self

    def to_keepass(self, entry: KeePassEntry):

        self.exists_in_keepass = True
        for field_name, field_value in self.data.items():
            if field_name in keepass_default_fields:
                logging.debug('extracting key %s from keypass file ...', field_name)
                if field_value is not None:
                    setattr(entry, field_name, field_value)
            else:
                entry.custom_properties[field_name] = field_value
         
    @classmethod
    def from_hashicorp_vault(class_name, secret_path: str, secret: HashiCorpVaultSecret) -> 'SyncKeyModel':
        self = SyncKeyModel(full_path= secret_path)
        self.exists_in_vault = True
        self.name = re.match(extract_key_from_path, secret_path).groups()[0]
        self.data = secret.data
        self.last_modification_time = parser.parse(secret.metadata['created_time']).timestamp()
        return self


