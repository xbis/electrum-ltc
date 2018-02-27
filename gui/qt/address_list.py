#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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
import webbrowser

from .util import *
from electrum_ltc.i18n import _
from electrum_ltc.util import block_explorer_URL
from electrum_ltc.plugins import run_hook
from electrum_ltc.bitcoin import is_address


class AddressList(MyTreeWidget):
    filter_columns = [0, 1, 2]  # Address, Label, Balance

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 1)
        self.refresh_headers()
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.show_change = 0
        self.show_used = 0
        self.jh_is_loading = False
        self.change_button = QComboBox(self)
        self.change_button.currentIndexChanged.connect(self.toggle_change)
        for t in [_('Receiving'), _('Change'), _('All')]:
            self.change_button.addItem(t)
        self.used_button = QComboBox(self)
        self.used_button.currentIndexChanged.connect(self.toggle_used)
        for t in [_('All'), _('Unused'), _('Funded'), _('Used')]:
            self.used_button.addItem(t)

    def get_list_header(self):
        refresh_button = EnterButton(_("JH Refresh"), self.do_refresh)
        refresh_button.setToolTip(_('Refresh HD wallet balances.'))

        return QLabel(_("Filter:")), self.change_button, self.used_button, refresh_button

    def do_refresh(self):
        if self.jh_is_loading:
            self.parent.show_error(_('Synchronization in process. Please wait'))
            return

        self.jh_is_loading = True
        self.update()

        def a():
            currency = "BTC"
            jh_host = self.config.get('jh_host', '')
            jh_key = self.config.get('jh_key', '')
            # jh_secret = self.config.get('jh_secret','')

            jh_host = jh_host.rstrip('/')
            api_route = jh_host + "/export/address/"+currency

            # if jh_host == '' or jh_key == '' or jh_secret == '':
            if jh_host == '' or jh_key == '':
                return self.parent.show_error(_('Check your Jackhammer preferences'))

            headers = {
                'x-api-key': jh_key
            }

            r = requests.get(api_route, headers=headers)
            if r.status_code is not requests.codes.ok:
                return self.parent.show_error(_('Bad response from Jackhammer. Code: ') + ("%s" % r.status_code) + r.text)

            response = r.json()
            print(response)
            if response is None or not len(response):
                return

            payload = []
            for addr in response:
                print(addr)
                path = addr.get('hd_key', '')
                address = addr.get('address', '')

                if path == '':
                    return self.parent.show_error(_('Bad response from Jackhammer'))

                hd_address = self.wallet.create_new_hd_address(path, False)
                if address != hd_address:
                    return self.parent.show_error(_('Wrong address was generated.'))

                self.wallet.create_new_hd_address(path, True)

                payload.append(hd_address)

            r = requests.post(api_route, headers=headers, data={'addresses' : payload})
            if r.status_code is not requests.codes.ok:
                return self.parent.show_error(_('Bad response from Jackhammer. Code: ') + ("%s" % r.status_code) + r.text)


        try:
            a()
        except Exception as e:
            print(e)
            self.parent.show_error(_('Exception during request '))

        self.jh_is_loading = False
        self.update()

    def refresh_headers(self):
        headers = [ _('Address'), _('Label'), _('Balance')]
        fx = self.parent.fx
        if fx and fx.get_fiat_address_config():
            headers.extend([_(fx.get_currency()+' Balance')])
        headers.extend([_('Tx')])
        self.update_headers(headers)

    def toggle_change(self, state):
        if state == self.show_change:
            return
        self.show_change = state
        self.update()

    def toggle_used(self, state):
        if state == self.show_used:
            return
        self.show_used = state
        self.update()

    def on_update(self):
        self.wallet = self.parent.wallet
        item = self.currentItem()
        current_address = item.data(0, Qt.UserRole) if item else None
        if self.show_change == 0:
            addr_list = self.wallet.get_receiving_addresses()
        elif self.show_change == 1:
            addr_list = self.wallet.get_change_addresses()
        else:
            addr_list = self.wallet.get_addresses()
        self.clear()

        if self.jh_is_loading:
            address_item = QTreeWidgetItem(["Loading addresses from Jackhammer", "", "", ""])
            self.addChild(address_item)
            return

        for address in addr_list:
            num = len(self.wallet.history.get(address,[]))
            is_used = self.wallet.is_used(address)
            label = self.wallet.labels.get(address, '')
            c, u, x = self.wallet.get_addr_balance(address)
            balance = c + u + x
            if self.show_used == 1 and (balance or is_used):
                continue
            if self.show_used == 2 and balance == 0:
                continue
            if self.show_used == 3 and not is_used:
                continue
            balance_text = self.parent.format_amount(balance)
            fx = self.parent.fx
            if fx and fx.get_fiat_address_config():
                rate = fx.exchange_rate()
                fiat_balance = fx.value_str(balance, rate)
                address_item = QTreeWidgetItem([address, label, balance_text, fiat_balance, "%d"%num])
                address_item.setTextAlignment(3, Qt.AlignRight)
            else:
                address_item = QTreeWidgetItem([address, label, balance_text, "%d"%num])
                address_item.setTextAlignment(2, Qt.AlignRight)
            address_item.setFont(0, QFont(MONOSPACE_FONT))
            address_item.setData(0, Qt.UserRole, address)
            address_item.setData(0, Qt.UserRole+1, True) # label can be edited
            if self.wallet.is_frozen(address):
                address_item.setBackground(0, ColorScheme.BLUE.as_color(True))
            if self.wallet.is_beyond_limit(address):
                address_item.setBackground(0, ColorScheme.RED.as_color(True))
            self.addChild(address_item)
            if address == current_address:
                self.setCurrentItem(address_item)

    def create_menu(self, position):
        from electrum_ltc.wallet import Multisig_Wallet
        is_multisig = isinstance(self.wallet, Multisig_Wallet)
        can_delete = self.wallet.can_delete_address()
        selected = self.selectedItems()
        multi_select = len(selected) > 1
        addrs = [item.text(0) for item in selected]
        if not addrs:
            return
        if not multi_select:
            item = self.itemAt(position)
            col = self.currentColumn()
            if not item:
                return
            addr = addrs[0]
            if not is_address(addr):
                item.setExpanded(not item.isExpanded())
                return

        menu = QMenu()
        if not multi_select:
            column_title = self.headerItem().text(col)
            copy_text = item.text(col)
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(copy_text))
            menu.addAction(_('Details'), lambda: self.parent.show_address(addr))
            if col in self.editable_columns:
                menu.addAction(_("Edit {}").format(column_title), lambda: self.editItem(item, col))
            menu.addAction(_("Request payment"), lambda: self.parent.receive_at(addr))
            if self.wallet.can_export():
                menu.addAction(_("Private key"), lambda: self.parent.show_private_key(addr))
            if not is_multisig and not self.wallet.is_watching_only():
                menu.addAction(_("Sign/verify message"), lambda: self.parent.sign_verify_message(addr))
                menu.addAction(_("Encrypt/decrypt message"), lambda: self.parent.encrypt_message(addr))
            if can_delete:
                menu.addAction(_("Remove from wallet"), lambda: self.parent.remove_address(addr))
            addr_URL = block_explorer_URL(self.config, 'addr', addr)
            if addr_URL:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(addr_URL))

            if not self.wallet.is_frozen(addr):
                menu.addAction(_("Freeze"), lambda: self.parent.set_frozen_state([addr], True))
            else:
                menu.addAction(_("Unfreeze"), lambda: self.parent.set_frozen_state([addr], False))

        coins = self.wallet.get_utxos(addrs)
        if coins:
            menu.addAction(_("Spend from"), lambda: self.parent.spend_coins(coins))

        run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # labels for headings, e.g. "receiving" or "used" should not be editable
        return item.childCount() == 0
