from electrum_rutanio.i18n import _
from electrum_rutanio.util import SSLContextSafe

from xmlrpc.client import ServerProxy

fullname = _('Cosigner Pool')
description = ' '.join([
    _("This plugin facilitates the use of multi-signatures wallets."),
    _("It sends and receives partially signed transactions from/to your cosigner wallet."),
    _("Transactions are encrypted and stored on a remote server.")
])
#requires_wallet_type = ['2of2', '2of3']
available_for = ['qt']

# get ssl context with known cert trust store location
context = SSLContextSafe.get_context()

server = ServerProxy('https://cosigner.rutax.co/', allow_none=True, verbose=False, use_datetime=True, context=context)