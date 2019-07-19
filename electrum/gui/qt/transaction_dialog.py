#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import copy
import datetime
import json
import traceback

from xmlrpc.client import ServerProxy

from PyQt5.QtCore import QSize, QTimer
from PyQt5.QtGui import QTextCharFormat, QBrush, QFont
from PyQt5.QtWidgets import (QDialog, QLabel, QPushButton, QHBoxLayout, QVBoxLayout,
                             QTextEdit)
import qrcode
from qrcode import exceptions

from electrum_exos import util, keystore, ecc, bip32, crypto
from electrum_exos.bitcoin import base_encode
from electrum_exos.i18n import _
from electrum_exos.plugin import run_hook
from electrum_exos import simple_config
from electrum_exos.util import bfh, bh2u
from electrum_exos.transaction import SerializationError, Transaction
from electrum_exos.wallet import Multisig_Wallet
from electrum_exos.plugins.cosigner_pool import server	

from .util import (MessageBoxMixin, read_QIcon, Buttons, CopyButton,
                   MONOSPACE_FONT, ColorScheme, ButtonsLineEdit)


SAVE_BUTTON_ENABLED_TOOLTIP = _("Save transaction offline")
SAVE_BUTTON_DISABLED_TOOLTIP = _("Please sign this transaction in order to save it")
DURATION_INT = 60 * 10 

dialogs = []  # Otherwise python randomly garbage collects the dialogs...

def show_transaction_timeout(tx, parent, desc=None, prompt_if_unsaved=False):
    try:
        d = TxDialogTimeout(tx, parent, desc, prompt_if_unsaved)
    except SerializationError as e:
        traceback.print_exc(file=sys.stderr)
        parent.show_critical(_("EXOS-Electrum was unable to deserialize the transaction:") + "\n" + str(e))
    else:
        dialogs.append(d)
        d.show()
        return d


def show_transaction(tx, parent, desc=None, prompt_if_unsaved=False):
    try:
        d = TxDialog(tx, parent, desc, prompt_if_unsaved)
    except SerializationError as e:
        traceback.print_exc(file=sys.stderr)
        parent.show_critical(_("EXOS-Electrum was unable to deserialize the transaction:") + "\n" + str(e))
    else:
        dialogs.append(d)
        d.show()

class TxDialog(QDialog, MessageBoxMixin):

    def __init__(self, tx, parent, desc, prompt_if_unsaved):
        '''Transactions in the wallet will show their description.
        Pass desc to give a description for txs not yet in the wallet.
        '''
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)
        # Take a copy; it might get updated in the main window by
        # e.g. the FX plugin.  If this happens during or after a long
        # sign operation the signatures are lost.
        self.tx = tx = copy.deepcopy(tx)  # type: Transaction 
        
        try:
            self.tx.deserialize()
        except BaseException as e:
            raise SerializationError(e)
        self.main_window = parent
        self.wallet = parent.wallet
        self.prompt_if_unsaved = prompt_if_unsaved
        self.saved = False
        self.desc = desc
        

        # store the keyhash and cosigners for current wallet
        self.keyhashes = set()
        self.cosigner_list = set()
        if type(self.wallet) == Multisig_Wallet:
            for key, keystore in self.wallet.keystores.items():
                xpub = keystore.get_master_public_key()
                K = bip32.deserialize_xpub(xpub)[-1]
                _hash = bh2u(crypto.sha256d(K))
                if not keystore.is_watching_only():
                    self.keyhashes.add(_hash)
                else:
                    self.cosigner_list.add(_hash)

        # if the wallet can populate the inputs with more info, do it now.
        # as a result, e.g. we might learn an imported address tx is segwit,
        # in which case it's ok to display txid
        tx.add_inputs_info(self.wallet)

        self.setMinimumWidth(950)
        self.setWindowTitle(_("Transaction"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e  = ButtonsLineEdit()
        qr_show = lambda: parent.show_qrcode(str(self.tx_hash_e.text()), 'Transaction ID', parent=self)
        qr_icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.tx_hash_e.addButton(qr_icon, qr_show, _("Show as QR code"))
        self.tx_hash_e.setReadOnly(True)
        vbox.addWidget(self.tx_hash_e)
        self.tx_desc = QLabel()
        vbox.addWidget(self.tx_desc)
        self.status_label = QLabel()
        vbox.addWidget(self.status_label)
        self.date_label = QLabel()
        vbox.addWidget(self.date_label)
        self.amount_label = QLabel()
        vbox.addWidget(self.amount_label)
        self.size_label = QLabel()
        vbox.addWidget(self.size_label)
        self.fee_label = QLabel()
        vbox.addWidget(self.fee_label)

        self.add_io(vbox)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.do_broadcast)

        self.save_button = b = QPushButton(_("Save"))
        save_button_disabled = not tx.is_complete()
        b.setDisabled(save_button_disabled)
        if save_button_disabled:
            b.setToolTip(SAVE_BUTTON_DISABLED_TOOLTIP)
        else:
            b.setToolTip(SAVE_BUTTON_ENABLED_TOOLTIP)
        b.clicked.connect(self.save)

        self.export_button = b = QPushButton(_("Export"))
        b.clicked.connect(self.export)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.qr_button = b = QPushButton()
        b.setIcon(read_QIcon(qr_icon))
        b.clicked.connect(self.show_qr)

        self.copy_button = CopyButton(lambda: str(self.tx), parent.app)

        # Action buttons
        self.buttons = [self.sign_button, self.broadcast_button, self.cancel_button]
        # Transaction sharing buttons
        self.sharing_buttons = [self.copy_button, self.qr_button, self.export_button, self.save_button]

        run_hook('transaction_dialog', self)

        hbox = QHBoxLayout()
        hbox.addLayout(Buttons(*self.sharing_buttons))
        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        vbox.addLayout(hbox)
        self.update()

    def do_broadcast(self):
        self.main_window.push_top_level_window(self)
        try:
            self.main_window.broadcast_transaction(self.tx, self.desc)
        finally:
            self.main_window.pop_top_level_window(self)

            # on broadcast garbage collect 'all' keys
            if type(self.wallet) == Multisig_Wallet:
                for keyhash in self.keyhashes:
                    server.delete(keyhash)
                    server.delete(keyhash+'_pick')
                    server.delete(keyhash+'_signed')
                    server.delete(keyhash+'_lock')
                for keyhash in self.cosigner_list:
                    server.delete(keyhash)
                    server.delete(keyhash+'_pick')
                    server.delete(keyhash+'_signed')
                    server.delete(keyhash+'_lock')

                    
        self.saved = True
        self.update()

    def closeEvent(self, event):
        if (self.prompt_if_unsaved and not self.saved
                and not self.question(_('This transaction is not saved. Close anyway?'), title=_("Warning"))):
            event.ignore()
        else:
            event.accept()
            try:
                dialogs.remove(self)

                if type(self.wallet) == Multisig_Wallet:
                    # set pick flag to true
                    for keyhash in self.keyhashes:
                        server.put(keyhash+'_pick', 'True')

            except ValueError:
                pass  # was not in list already

    def reject(self):
        # Override escape-key to close normally (and invoke closeEvent)
        self.close()

    def show_qr(self):
        text = bfh(str(self.tx))
        text = base_encode(text, base=43)
        try:
            self.main_window.show_qrcode(text, 'Transaction', parent=self)
        except qrcode.exceptions.DataOverflowError:
            self.show_error(_('Failed to display QR code.') + '\n' +
                            _('Transaction is too large in size.'))
        except Exception as e:
            self.show_error(_('Failed to display QR code.') + '\n' + str(e))

    def sign(self):
        def sign_done(success):
            # note: with segwit we could save partially signed tx, because they have a txid
            if self.tx.is_complete():
                self.prompt_if_unsaved = True
                self.saved = False
                self.save_button.setDisabled(False)
                self.save_button.setToolTip(SAVE_BUTTON_ENABLED_TOOLTIP)

            self.update()
            self.main_window.pop_top_level_window(self)

        self.sign_button.setDisabled(True)
        self.main_window.push_top_level_window(self)
        self.main_window.sign_tx(self.tx, sign_done)

    def save(self):
        self.main_window.push_top_level_window(self)
        if self.main_window.save_transaction_into_wallet(self.tx):
            self.save_button.setDisabled(True)
            self.saved = True
        self.main_window.pop_top_level_window(self)


    def export(self):
        name = 'signed_%s.txn' % (self.tx.txid()[0:8]) if self.tx.is_complete() else 'unsigned.txn'
        fileName = self.main_window.getSaveFileName(_("Select where to save your signed transaction"), name, "*.txn")
        if fileName:
            with open(fileName, "w+") as f:
                f.write(json.dumps(self.tx.as_dict(), indent=4) + '\n')
            self.show_message(_("Transaction exported successfully"))
            self.saved = True

    def update(self):
        desc = self.desc
        base_unit = self.main_window.base_unit()
        format_amount = self.main_window.format_amount
        tx_hash, status, label, can_broadcast, can_rbf, amount, fee, height, conf, timestamp, exp_n = self.wallet.get_tx_info(self.tx)
        size = self.tx.estimated_size()
        self.broadcast_button.setEnabled(can_broadcast)
        can_sign = not self.tx.is_complete() and \
            (self.wallet.can_sign(self.tx) or bool(self.main_window.tx_external_keypairs))
        self.sign_button.setEnabled(can_sign)
        self.tx_hash_e.setText(tx_hash or _('Unknown'))
        if desc is None:
            self.tx_desc.hide()
        else:
            self.tx_desc.setText(_("Description") + ': ' + desc)
            self.tx_desc.show()
        self.status_label.setText(_('Status:') + ' ' + status)

        if timestamp:
            time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
            self.date_label.setText(_("Date: {}").format(time_str))
            self.date_label.show()
        elif exp_n:
            text = '%.2f MB'%(exp_n/1000000)
            self.date_label.setText(_('Position in mempool: {} from tip').format(text))
            self.date_label.show()
        else:
            self.date_label.hide()
        if amount is None:
            amount_str = _("Transaction unrelated to your wallet")
        elif amount > 0:
            amount_str = _("Amount received:") + ' %s'% format_amount(amount) + ' ' + base_unit
        else:
            amount_str = _("Amount sent:") + ' %s'% format_amount(-amount) + ' ' + base_unit
        size_str = _("Size:") + ' %d bytes'% size
        fee_str = _("Fee") + ': %s' % (format_amount(fee) + ' ' + base_unit if fee is not None else _('unknown'))
        if fee is not None:
            fee_rate = fee/size*1000
            fee_str += '  ( %s ) ' % self.main_window.format_fee_rate(fee_rate)
            confirm_rate = simple_config.FEERATE_WARNING_HIGH_FEE
            if fee_rate > confirm_rate:
                fee_str += ' - ' + _('Warning') + ': ' + _("high fee") + '!'
        self.amount_label.setText(amount_str)
        self.fee_label.setText(fee_str)
        self.size_label.setText(size_str)
        run_hook('transaction_dialog_update', self)

    def add_io(self, vbox):
        if self.tx.locktime > 0:
            vbox.addWidget(QLabel("LockTime: %d\n" % self.tx.locktime))

        vbox.addWidget(QLabel(_("Inputs") + ' (%d)'%len(self.tx.inputs())))
        ext = QTextCharFormat()
        rec = QTextCharFormat()
        rec.setBackground(QBrush(ColorScheme.GREEN.as_color(background=True)))
        rec.setToolTip(_("Wallet receive address"))
        chg = QTextCharFormat()
        chg.setBackground(QBrush(ColorScheme.YELLOW.as_color(background=True)))
        chg.setToolTip(_("Wallet change address"))
        twofactor = QTextCharFormat()
        twofactor.setBackground(QBrush(ColorScheme.BLUE.as_color(background=True)))
        twofactor.setToolTip(_("TrustedCoin (2FA) fee for the next batch of transactions"))

        def text_format(addr):
            if self.wallet.is_mine(addr):
                return chg if self.wallet.is_change(addr) else rec
            elif self.wallet.is_billing_address(addr):
                return twofactor
            return ext

        def format_amount(amt):
            return self.main_window.format_amount(amt, whitespaces=True)

        i_text = QTextEditWithDefaultSize()
        i_text.setFont(QFont(MONOSPACE_FONT))
        i_text.setReadOnly(True)
        cursor = i_text.textCursor()
        for x in self.tx.inputs():
            if x['type'] == 'coinbase':
                cursor.insertText('coinbase')
            else:
                prevout_hash = x.get('prevout_hash')
                prevout_n = x.get('prevout_n')
                cursor.insertText(prevout_hash + ":%-4d " % prevout_n, ext)
                addr = self.wallet.get_txin_address(x)
                if addr is None:
                    addr = ''
                cursor.insertText(addr, text_format(addr))
                if x.get('value'):
                    cursor.insertText(format_amount(x['value']), ext)
            cursor.insertBlock()

        vbox.addWidget(i_text)
        vbox.addWidget(QLabel(_("Outputs") + ' (%d)'%len(self.tx.outputs())))
        o_text = QTextEditWithDefaultSize()
        o_text.setFont(QFont(MONOSPACE_FONT))
        o_text.setReadOnly(True)
        cursor = o_text.textCursor()
        for o in self.tx.get_outputs_for_UI():
            addr, v = o.address, o.value
            cursor.insertText(addr, text_format(addr))
            if v is not None:
                cursor.insertText('\t', ext)
                cursor.insertText(format_amount(v), ext)
            cursor.insertBlock()
        vbox.addWidget(o_text)

class TxDialogTimeout(TxDialog):
    
    def __init__(self, tx, parent, desc, prompt_if_unsaved):
        '''Transactions in the wallet will show their description.
        Pass desc to give a description for txs not yet in the wallet.
        '''
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)
        # Take a copy; it might get updated in the main window by
        # e.g. the FX plugin.  If this happens during or after a long
        # sign operation the signatures are lost.
        self.tx = tx = copy.deepcopy(tx)  # type: Transaction
        try:
            self.tx.deserialize()
        except BaseException as e:
            raise SerializationError(e)
        self.main_window = parent
        self.wallet = parent.wallet
        self.prompt_if_unsaved = prompt_if_unsaved
        self.saved = False
        self.desc = desc
        self.locks = {}

        # Set timeout flag 
        self.timed_out = False

        # store the keyhash and cosigners for current wallet
        self.keyhashes = set()
        self.cosigner_list = set()
        if type(self.wallet) == Multisig_Wallet:
            for key, keystore in self.wallet.keystores.items():
                xpub = keystore.get_master_public_key()
                K = bip32.deserialize_xpub(xpub)[-1]
                _hash = bh2u(crypto.sha256d(K))
                if not keystore.is_watching_only():
                    self.keyhashes.add(_hash)
                    self.locks[_hash] = server.get(_hash+'_lock')
                else:
                    self.cosigner_list.add(_hash)


        # if the wallet can populate the inputs with more info, do it now.
        # as a result, e.g. we might learn an imported address tx is segwit,
        # in which case it's ok to display txid
        tx.add_inputs_info(self.wallet)

        self.setMinimumWidth(950)
        self.setWindowTitle(_("Transaction"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e  = ButtonsLineEdit()
        qr_show = lambda: parent.show_qrcode(str(self.tx_hash_e.text()), 'Transaction ID', parent=self)
        qr_icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.tx_hash_e.addButton(qr_icon, qr_show, _("Show as QR code"))
        self.tx_hash_e.setReadOnly(True)
        vbox.addWidget(self.tx_hash_e)
        self.tx_desc = QLabel()
        vbox.addWidget(self.tx_desc)
        self.status_label = QLabel()
        vbox.addWidget(self.status_label)
        self.date_label = QLabel()
        vbox.addWidget(self.date_label)
        self.amount_label = QLabel()
        vbox.addWidget(self.amount_label)
        self.size_label = QLabel()
        vbox.addWidget(self.size_label)
        self.fee_label = QLabel()
        vbox.addWidget(self.fee_label)

        self.add_io(vbox)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.do_broadcast)

        self.save_button = b = QPushButton(_("Save"))
        save_button_disabled = not tx.is_complete()
        b.setDisabled(save_button_disabled)
        if save_button_disabled:
            b.setToolTip(SAVE_BUTTON_DISABLED_TOOLTIP)
        else:
            b.setToolTip(SAVE_BUTTON_ENABLED_TOOLTIP)
        b.clicked.connect(self.save)

        self.export_button = b = QPushButton(_("Export"))
        b.clicked.connect(self.export)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.qr_button = b = QPushButton()
        b.setIcon(read_QIcon(qr_icon))
        b.clicked.connect(self.show_qr)

        self.copy_button = CopyButton(lambda: str(self.tx), parent.app)

        # Action buttons
        self.buttons = [self.sign_button, self.broadcast_button, self.cancel_button]
        # Transaction sharing buttons
        self.sharing_buttons = [self.copy_button, self.qr_button, self.export_button, self.save_button]

        # Add label for countdown timer
        self.time_out_label = QLabel()
        vbox.addWidget(self.time_out_label)

        run_hook('transaction_dialog', self)

        hbox = QHBoxLayout()
        hbox.addLayout(Buttons(*self.sharing_buttons))
        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        vbox.addLayout(hbox)

        for _hash, expire in self.locks.items():
            if expire:
                self.time_left_int = int((DURATION_INT - (int(server.get_current_time()) - int(expire))))

        self.timer_start()
        self.update()

    def timer_start(self):
        #self.time_left_int = DURATION_INT

        self.my_qtimer = QTimer(self)
        self.my_qtimer.timeout.connect(self.timer_timeout)
        self.my_qtimer.start(1000)

        self.update()

    def timer_timeout(self):
        self.time_left_int -= 1

        if self.time_left_int == 0 and self.isVisible():
            self.timed_out = True
            self.close()

        self.update()

    def release_locks(self):
        if type(self.wallet) == Multisig_Wallet:
            for keyhash in self.keyhashes:
                # delete lock blocking other wallets from opening TX dialog
                server.delete(keyhash+'_lock')
                # set pick flag to true
                server.put(keyhash+'_pick', 'True')
                # set graceful shutdown flag to down to signify a graceful shutdown
                server.put(keyhash+'_shutdown', 'down')

    def closeEvent(self, event):
        if (self.timed_out):
            event.accept()
            try:
                dialogs.remove(self)
                self.release_locks()
                return
            except ValueError:
                pass  # was not in list already

        if (self.prompt_if_unsaved and not self.saved
                and not self.question(_('This transaction is not saved. Close anyway?'), title=_("Warning"))):
            event.ignore()
        else:
            event.accept()
            try:
                dialogs.remove(self)
                self.release_locks()
            except ValueError:
                pass  # was not in list already

    def update(self):
        desc = self.desc
        base_unit = self.main_window.base_unit()
        format_amount = self.main_window.format_amount
        tx_hash, status, label, can_broadcast, can_rbf, amount, fee, height, conf, timestamp, exp_n = self.wallet.get_tx_info(self.tx)
        size = self.tx.estimated_size()
        self.broadcast_button.setEnabled(can_broadcast)
        can_sign = not self.tx.is_complete() and \
            (self.wallet.can_sign(self.tx) or bool(self.main_window.tx_external_keypairs))
        self.sign_button.setEnabled(can_sign)
        self.tx_hash_e.setText(tx_hash or _('Unknown'))
        if desc is None:
            self.tx_desc.hide()
        else:
            self.tx_desc.setText(_("Description") + ': ' + desc)
            self.tx_desc.show()
        self.status_label.setText(_('Status:') + ' ' + status)

        if timestamp:
            time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
            self.date_label.setText(_("Date: {}").format(time_str))
            self.date_label.show()
        elif exp_n:
            text = '%.2f MB'%(exp_n/1000000)
            self.date_label.setText(_('Position in mempool: {} from tip').format(text))
            self.date_label.show()
        else:
            self.date_label.hide()
        if amount is None:
            amount_str = _("Transaction unrelated to your wallet")
        elif amount > 0:
            amount_str = _("Amount received:") + ' %s'% format_amount(amount) + ' ' + base_unit
        else:
            amount_str = _("Amount sent:") + ' %s'% format_amount(-amount) + ' ' + base_unit
        size_str = _("Size:") + ' %d bytes'% size
        fee_str = _("Fee") + ': %s' % (format_amount(fee) + ' ' + base_unit if fee is not None else _('unknown'))
        if fee is not None:
            fee_rate = fee/size*1000
            fee_str += '  ( %s ) ' % self.main_window.format_fee_rate(fee_rate)
            confirm_rate = simple_config.FEERATE_WARNING_HIGH_FEE
            if fee_rate > confirm_rate:
                fee_str += ' - ' + _('Warning') + ': ' + _("high fee") + '!'
        self.amount_label.setText(amount_str)
        self.fee_label.setText(fee_str)

        # Set label for countdown timer and on update
        mins, secs = divmod(self.time_left_int, 60)
        timeformat = 'Time left: {:02d}:{:02d}'.format(mins, secs)
        #countdown = _("Time left") + ': %s' % (str(self.time_left_int))
        self.time_out_label.setText(timeformat)

        self.size_label.setText(size_str)
        run_hook('transaction_dialog_update', self)
        

class QTextEditWithDefaultSize(QTextEdit):
    def sizeHint(self):
        return QSize(0, 100)
