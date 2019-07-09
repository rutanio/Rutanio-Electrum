from electrum_exos.i18n import _
import ssl 

from xmlrpc.client import ServerProxy

fullname = _('Cosigner Pool')
description = ' '.join([
    _("This plugin facilitates the use of multi-signatures wallets."),
    _("It sends and receives partially signed transactions from/to your cosigner wallet."),
    _("Transactions are encrypted and stored on a remote server.")
])
#requires_wallet_type = ['2of2', '2of3']
available_for = ['qt']

server = ServerProxy('https://cosigner.exos.to/', allow_none=True, verbose=False, use_datetime=True,context=ssl._create_unverified_context())