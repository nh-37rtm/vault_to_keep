from pykeepass import PyKeePass, create_database
from pykeepass.entry import Entry as KeePassEntry

import hvac
import os
import logging
import pydantic
from model.SyncKeyModels import SyncKeyModel, HashiCorpVaultSecret, KeePassEntry

import typing as t


from collections import deque


class KeepassSyncFromVault:

    _pykeepass_instance = None
    _hcvault_client_instance = None

    def __init__(self, keepass_file: str, keepass_password: str):

        logging.info("initialising keepass file ...")
        if os.path.exists(keepass_file):
            self._pykeepass_instance = PyKeePass(filename=keepass_file, password=keepass_password)
        else:
            logging.info(' %s do not exists, creating ...', keepass_file)
            self._pykeepass_instance = create_database( filename= keepass_file, 
                                 password= keepass_password)
            
        logging.info('connecting keyvault ...')

        self._hcvault_client_instance = hvac.Client(url='http://localhost:8200', verify= False)
        self._hcvault_client_instance.token = "vault-plaintext-root-token"
        logging.info('hcvault is authenticated ?: %s', self._hcvault_client_instance.is_authenticated())

        # hcvault_client_instance.sys.tune_mount_configuration(
        #     path='secret',
        #     default_lease_ttl='3600s',
        #     max_lease_ttl='8600s',
        # )
        
        # res = hcvault_client_instance.secrets.kv.read_secret_version( path="/my/secret")
        # res = hcvault_client_instance.secrets.kv.v2.list_secrets(path= "my/")
            
        queue: deque = deque([ '/' ])
        vault_leafs = list()
  
        logging.info('exploring vault secrets ...')
        while (not len(queue) == 0):
            path_element = queue.pop()
            res = self._hcvault_client_instance.secrets.kv.v2.list_secrets(path= path_element)
            
            for keepass_secret in res['data']['keys']:
                joined_path: str = os.path.join(path_element, keepass_secret)
                if keepass_secret.endswith('/'):
                    queue.append(joined_path)
                else:
                    vault_leafs.append(joined_path)
        
        logging.info('found %d vault secrets', len(vault_leafs))
        logging.info('indexing vault keys ...')
        secrets_by_path : dict[str, SyncKeyModel] = dict()
        for secret_path in vault_leafs:
            logging.info('copying secret %s', secret_path)
            secret = self._hcvault_client_instance.secrets.kv.read_secret_version(path=secret_path)

            hsecret = HashiCorpVaultSecret(**secret['data'])
            keyvault_secret = SyncKeyModel.from_hashicorp_vault(secret_path, hsecret)
            secrets_by_path[keyvault_secret.full_path] = keyvault_secret

        stats = [0,0]
        logging.info('comparing with keepass entries ...')
        for entry in self._pykeepass_instance.entries:
            keepass_entry: KeePassEntry = entry
            keepass_secret = SyncKeyModel.from_keepass(keepass_entry)
            logging.info('copying secret %s', keepass_secret.full_path)
            if keepass_secret.full_path in secrets_by_path:
                logging.info( '%s secret already exists in vault', keepass_secret.full_path )
                vault_secret = secrets_by_path[keepass_secret.full_path]
                if ( keepass_secret == secrets_by_path[keepass_secret.full_path] ):
                    logging.info('no changes found, skipping ...')
                    secrets_by_path[keepass_secret.full_path].exists_in_keepass = True
                    secrets_by_path[keepass_secret.full_path].exists_in_vault = True
                    stats[0] += 1
                    continue
                if ( keepass_secret.last_modification_time >  vault_secret.last_modification_time ) :
                    logging.info('keepass entry time is newer, replacing entry ...')
                    secrets_by_path[keepass_secret.full_path] = keepass_secret
                    secrets_by_path[keepass_secret.full_path].exists_in_vault = False
                    stats[1] += 1
                if ( keepass_secret.last_modification_time < vault_secret.last_modification_time ) :
                    logging.info('keepass entry time is older, tagging for update ...')
                    secrets_by_path[keepass_secret.full_path].exists_in_keepass = False
                    stats[1] += 1
            else :
                secrets_by_path[keepass_secret.full_path] = keepass_secret

        logging.info('%d entrie(s) created/modified, %d unchanged', stats[1], stats[0])

        for path, secret in secrets_by_path.items():
            if secret.exists_in_keepass is False:
                 
                group_path = path[slice(0, path.rindex('/'))]
                keepass_group_object = self._keepass_ensure_group_exists( group_path )
                keepass_entry = self._pykeepass_instance.find_entries_by_path( path.split('/')[1:] )

                if keepass_entry is None :
                    entry = self._pykeepass_instance.add_entry(
                        destination_group= keepass_group_object,
                        title= secret.name,
                        username='', password= ''
                    )
                else:
                    logging.info('updating keepass entry %s ...', path)
                    secret.to_keepass(keepass_entry)

            if secret.exists_in_vault is False:
                self._hcvault_client_instance.secrets.kv.v2.create_or_update_secret(
                    path= path,
                    secret = secret.data)
                
        self._pykeepass_instance.save()


    def _keepass_ensure_group_exists( self, group_path: str) -> t.Any:
        parent_group = self._pykeepass_instance.root_group
        for group_element in group_path.split('/'):

            if not group_element:
                continue
            current_group = self._pykeepass_instance.find_groups(group= parent_group, name=group_element, first= True)

            if current_group is None:
                logging.info('creating group %s', group_element)
                current_group = self._pykeepass_instance.add_group(
                    destination_group= parent_group, group_name= group_element)

            parent_group = current_group
        
        return parent_group
