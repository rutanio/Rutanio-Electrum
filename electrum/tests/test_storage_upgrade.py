import shutil
import tempfile

from electrum_exos.storage import WalletStorage
from electrum_exos.wallet import Wallet

from .test_wallet import WalletTestCase


# TODO add other wallet types: 2fa, xpub-only
# TODO hw wallet with client version 2.6.x (single-, and multiacc)
class TestStorageUpgrade(WalletTestCase):
    ##########
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from electrum_exos.plugin import Plugins
        from electrum_exos.simple_config import SimpleConfig

        cls.electrum_path = tempfile.mkdtemp()
        config = SimpleConfig({'electrum_path': cls.electrum_path})

        gui_name = 'cmdline'
        # TODO it's probably wasteful to load all plugins... only need Trezor
        Plugins(config, gui_name)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(cls.electrum_path)

    def _upgrade_storage(self, wallet_json, accounts=1):
        storage = self._load_storage_from_json_string(wallet_json, manual_upgrades=True)

        if accounts == 1:
            self.assertFalse(storage.requires_split())
            if storage.requires_upgrade():
                storage.upgrade()
                self._sanity_check_upgraded_storage(storage)
        else:
            self.assertTrue(storage.requires_split())
            new_paths = storage.split_accounts()
            self.assertEqual(accounts, len(new_paths))
            for new_path in new_paths:
                new_storage = WalletStorage(new_path, manual_upgrades=False)
                self._sanity_check_upgraded_storage(new_storage)

    def _sanity_check_upgraded_storage(self, storage):
        self.assertFalse(storage.requires_split())
        self.assertFalse(storage.requires_upgrade())
        w = Wallet(storage)

    def _load_storage_from_json_string(self, wallet_json, manual_upgrades=True):
        with open(self.wallet_path, "w") as f:
            f.write(wallet_json)
        storage = WalletStorage(self.wallet_path, manual_upgrades=manual_upgrades)
        return storage
