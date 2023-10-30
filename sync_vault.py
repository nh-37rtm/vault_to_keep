
from lib.KeepassSyncFromVault import KeepassSyncFromVault
import logging

logging.basicConfig(level= logging.DEBUG )

instance = KeepassSyncFromVault(keepass_file= "./test.kdbx", keepass_password="password")

logging.info('ending ...')




