from pykeepass import PyKeePass, create_database
from pykeepass.entry import Entry as KeePassEntry

import hvac
import os
import logging
import pydantic
from model.SyncKeyModels import SyncKeyModel, HashiCorpVaultSecret, KeePassEntry


from collections import deque


class KeepassSyncFromVault:

    pykeepass_instance = None
    hcvault_client_instance = None

    def __init__(self, keepass_file: str, keepass_password: str):

        logging.info("initialising keepass file ...")
        if os.path.exists(keepass_file):
            pykeepass_instance  = PyKeePass(filename=keepass_file, password=keepass_password)
        else:
            logging.info(f" {keepass_file} do not exists, creating ...")
            pykeepass_instance  = create_database( filename= keepass_file, 
                                 password= keepass_password)
            
        logging.info('connecting keyvault ...')

        hcvault_client_instance = hvac.Client(url='http://localhost:8200', verify= False)
        hcvault_client_instance.token = "vault-plaintext-root-token"
        logging.info(f'hcvault is authenticated ?: {hcvault_client_instance.is_authenticated()}')

        # hcvault_client_instance.sys.tune_mount_configuration(
        #     path='secret',
        #     default_lease_ttl='3600s',
        #     max_lease_ttl='8600s',
        # )
        
        res = hcvault_client_instance.secrets.kv.read_secret_version( path="/my/secret")
        res = hcvault_client_instance.secrets.kv.v2.list_secrets(path= "my/")
        
        entries_sync = dict()
        
        queue: deque = deque([ '/' ])
        vault_leafs = list()
        secrets_metas = dict()

        while (not len(queue) == 0):
            path_element = queue.pop()
            res = hcvault_client_instance.secrets.kv.v2.list_secrets(path= path_element)
            
            for keepass_secret in res['data']['keys']:
                joined_path: str = os.path.join(path_element, keepass_secret)
                if keepass_secret.endswith('/'):
                    queue.append(joined_path)
                else:
                    vault_leafs.append(joined_path)


        secrets_metas = {}
        secrets_by_path : dict[str, SyncKeyModel] = dict()
        for secret_path in vault_leafs:
            logging.info('copying secret %s', secret_path)
            secret = hcvault_client_instance.secrets.kv.read_secret_version(path=secret_path)

            hsecret = HashiCorpVaultSecret(**secret['data'])
            keyvault_secret = SyncKeyModel.from_hashicorp_vault(secret_path, hsecret)
            secrets_by_path[keyvault_secret.full_path] = keyvault_secret

        for entry in pykeepass_instance.entries:
            keepass_entry: KeePassEntry = entry
            keepass_secret = SyncKeyModel.from_keepass(keepass_entry)
            if keepass_secret.full_path in secrets_by_path:
                logging.info( '%s secret already exists', keepass_secret.full_path )
                vault_secret = secrets_by_path[keepass_secret.full_path]
                if ( keepass_secret.last_modification_time >  vault_secret.last_modification_time ) :
                    logging.info('keepass entry time is newer, replacing entry ...')
                    secrets_by_path[keepass_secret.full_path] = keepass_secret
            else :
                secrets_by_path[keepass_secret.full_path] = keepass_secret

         

        for path, secret in secrets_by_path.items():
            if secret.exists_in_keepass is False:
 
                group = pykeepass_instance.find_groups_by_path(path) \
                    or pykeepass_instance.add_group( 
                        destination_group= pykeepass_instance.root_group, group_name= path)
                
                entry = pykeepass_instance.add_entry(
                    destination_group= group,
                    title= secret.name,
                    username='', password= ''
                )
                secret.to_keepass(entry)

            if secret.exists_in_vault is False:
                hcvault_client_instance.secrets.kv.v2.create_or_update_secret(
                    path= path,
                    secret = secret.data)
                
        pykeepass_instance.save()
