from electrum_exos.i18n import _
import ssl 
import sys
from xmlrpc.client import ServerProxy
import platform

fullname = _('Cosigner Pool')
description = ' '.join([
    _("This plugin facilitates the use of multi-signatures wallets."),
    _("It sends and receives partially signed transactions from/to your cosigner wallet."),
    _("Transactions are encrypted and stored on a remote server.")
])
#requires_wallet_type = ['2of2', '2of3']
available_for = ['qt']

context = None

if sys.platform == 'darwin':
    context = ssl.SSLContext()
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    v, _, _ = platform.mac_ver()
    v = float('.'.join(v.split('.')[:2]))
    release = [10.12, 10.13, 10.14, 10.15]
    if v in release:
        context.load_verify_locations(cafile='/private/etc/ssl/cert.pem')    

server = ServerProxy('https://cosigner.exos.to/', allow_none=True, verbose=False, use_datetime=True, context=context)
