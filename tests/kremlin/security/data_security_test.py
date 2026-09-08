# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import json
import pytest
from unittest.mock import patch, MagicMock

from kremlin.security import data_security

def test_secure_kv_key():
    assert data_security._secure_kv_key("ns", "key") == b"ns:key"

def test_encrypt_decrypt_blob():
    blob = b"testblob"
    pwd = "password123!"
    enc = data_security.encrypt_blob(blob, pwd)
    assert enc["alg"] == "AESGCM"
    
    dec = data_security.decrypt_blob(enc, pwd)
    assert dec == blob
    
    with pytest.raises(ValueError):
        enc_bad = dict(enc)
        enc_bad["alg"] = "BAD"
        data_security.decrypt_blob(enc_bad, pwd)
        
    with pytest.raises(ValueError):
        enc_bad2 = dict(enc)
        enc_bad2["kdf"] = "BAD"
        data_security.decrypt_blob(enc_bad2, pwd)

@patch("kremlin.security.data_security.save_user_key_record")
@patch("kremlin.security.data_security.load_user_key_record")
def test_create_keypair(mock_load, mock_save, tmp_path):
    mock_load.return_value = None
    path = tmp_path / "key.json"
    node_id, pub, priv = data_security.create_keypair(str(path))
    assert len(pub) > 0
    assert len(priv) > 0
    mock_save.assert_called_once()

def test_security_check_attempt():
    data_security.Security.record_success("test")
    assert data_security.Security.check_attempt("test")
    
    for _ in range(5):
        try:
            data_security.Security.record_failure("test_fail")
        except ValueError:
            pass
    
    with pytest.raises(ValueError):
        data_security.Security.check_attempt("test_fail")

def test_validate_password_strength():
    ok, _ = data_security.Security.validate_password_strength("weak")
    assert not ok
    
    ok, res = data_security.Security.validate_password_strength("StrongPass123!")
    assert ok
    assert res["label"] in ["good", "strong", "excellent"]

def test_secure_erase():
    res = data_security.Security.secure_erase("test")
    assert isinstance(res, bytes)
    assert res == b"\x00" * 4
    
    res_bytes = data_security.Security.secure_erase(b"test")
    assert res_bytes == b"\x00" * 4
    
    assert data_security.Security.secure_erase(123) == 123

@patch("kremlin.security.data_security.kv_get")
@patch("kremlin.security.data_security.kv_put")
@patch("kremlin.security.data_security.kv_delete")
def test_secure_backend_kv(mock_del, mock_put, mock_get):
    data = {"a": 1}
    data_security._secure_backend_write("ns", "key", None, data)
    mock_put.assert_called()
    
    mock_get.return_value = json.dumps(data).encode("utf-8")
    read_data, is_file = data_security._secure_backend_read("ns", "key", None)
    assert read_data == data
    
    data_security._secure_backend_delete("ns", "key", None)
    mock_del.assert_called()

@patch("kremlin.security.data_security.kv_put")
@patch("kremlin.security.data_security.kv_get")
@patch("kremlin.security.data_security.kv_delete")
def test_secure_backend_read_write(mock_del, mock_get, mock_put, tmp_path):
    path = tmp_path / "test.json"
    path.write_text("{}", encoding="utf-8")
    data = {"a": 1}
    data_security._secure_backend_write("ns", "key", path, data)
    assert not path.exists()
    
    mock_get.return_value = json.dumps(data).encode("utf-8")
    read_data, _ = data_security._secure_backend_read("ns", "key", path)
    assert read_data == data
    
    data_security._secure_backend_delete("ns", "key", None)
    mock_del.assert_called()

@patch("kremlin.security.data_security._secure_backend_read")
@patch("kremlin.security.data_security._secure_backend_write")
def test_app_secret(mock_write, mock_read):
    mock_read.return_value = (None, False)
    
    # reset cache
    data_security._APP_SECRET_CACHE = None
    
    secret = data_security._get_app_secret_password()
    assert secret is not None
    assert data_security._app_secret_provider() == secret

def test_encrypt_decrypt_privkey():
    priv = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    pwd = "password123!"
    enc = data_security.encrypt_privkey(priv, pwd)
    dec = data_security.decrypt_privkey(enc, pwd)
    assert dec == priv

def test_pubkey_from_privhex():
    priv = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    pub = data_security.pubkey_from_privhex(priv)
    assert len(pub) == 33
    pub2 = data_security.pubkey_to_tsar_address(pub)
    assert isinstance(pub2, str)

@patch("kremlin.security.data_security.add_privkey_to_keystore")
def test_wallet_create(mock_add):
    mock_add.return_value = "tsar1test"
    addr, mnemo = data_security.Wallet.create("StrongPass123!")
    assert addr == "tsar1test"
    assert len(mnemo.split()) == 12

@patch("kremlin.security.data_security.add_privkey_to_keystore")
def test_wallet_create_from_privkey(mock_add):
    mock_add.return_value = "tsar1test"
    priv = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    addr = data_security.Wallet.create_from_privkey_hex(priv, "StrongPass123!")
    assert addr == "tsar1test"

@patch("kremlin.security.data_security.add_privkey_to_keystore")
def test_wallet_create_from_mnemonic(mock_add):
    mock_add.return_value = "tsar1test"
    mnemo = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    addr = data_security.Wallet.create_from_mnemonic(mnemo, "StrongPass123!")
    assert addr == "tsar1test"

@patch("kremlin.security.data_security.Security.log_security_event")
@patch("kremlin.security.data_security.load_keystore")
@patch("os.path.exists", return_value=True)
def test_wallet_unlock(mock_exists, mock_load, mock_log):
    priv = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    enc = data_security.encrypt_privkey(priv, "StrongPass123!")
    
    mock_load.return_value = {
        "wallets": {
            "tsar1test": {"payload": enc}
        },
        "default": "tsar1test"
    }
    
    res = data_security.Wallet.unlock("StrongPass123!", "tsar1test")
    assert res["private_key"] == priv
    assert res["address"] == "tsar1test"

@patch("kremlin.security.data_security.load_keystore")
@patch("kremlin.security.data_security.save_keystore")
def test_contacts(mock_save, mock_load):
    mock_load.return_value = {"contacts": {}}
    
    data_security.upsert_contact_in_keystore("tsar1test", "Test Alias", "pwd")
    mock_save.assert_called()
    
    mock_load.return_value = {"contacts": {"tsar1test": {"alias": "Test Alias"}}}
    contacts = data_security.list_contacts_in_keystore("pwd")
    assert contacts["tsar1test"] == "Test Alias"
    
    data_security.delete_contact_from_keystore("tsar1test", "pwd")
    mock_save.assert_called()

def test_history_cache(tmp_path):
    with patch("kremlin.security.data_security._hist_path", return_value=str(tmp_path / "hist.json")):
        items = [
            {"txid": "0"*64, "address": "tsar1", "amount": 100, "status": "confirmed"}
        ]
        
        added, updated = data_security.Wallet.history_cache_merge("tsar1", items)
        assert added == 1
        assert updated == 0
        
        res = data_security.Wallet.history_cache_list("tsar1")
        assert res["total"] == 1
        assert res["items"][0]["txid"] == "0"*64
        
        data_security.Wallet.history_cache_clear("tsar1")
        assert not os.path.exists(tmp_path / "hist.json")

def test_log_security_event(tmp_path):
    with patch("appdirs.user_log_dir", return_value=str(tmp_path)):
        data_security.Security.log_security_event("TEST_EVENT", "addr", "details")
        log_file = tmp_path / "security.log"
        assert log_file.exists()
        assert "TEST_EVENT" in log_file.read_text(encoding="utf-8")

# --- New tests for coverage ---

@patch("kremlin.security.data_security._secure_backend_read")
def test_secure_load_store(mock_read):
    # test decrypted
    enc = data_security.encrypt_blob(b'{"test": 1}', "pwd")
    mock_read.return_value = ({"enc": enc}, False)
    obj, migrated = data_security._secure_load("ns", "key", None, lambda x: "pwd", "prompt")
    assert obj["test"] == 1
    assert not migrated

    with pytest.raises(ValueError):
        data_security._secure_load("ns", "key", None, "not_callable", "prompt")

@patch("kremlin.security.data_security._secure_load")
@patch("kremlin.security.data_security._secure_store")
def test_chat_state_wallet_registry(mock_store, mock_load):
    mock_load.return_value = ({"blocked": ["alice"]}, False)
    state = data_security.load_chat_state()
    assert "alice" in state["blocked"]
    
    data_security.save_chat_state(state)
    mock_store.assert_called()
    
    mock_load.return_value = ({"wallets": ["tsar1test"]}, False)
    wallets = data_security.load_wallet_registry()
    assert "tsar1test" in wallets
    
    data_security.save_wallet_registry(["tsar1test", "tsar2test"])
    mock_store.assert_called()
    
    data_security.ensure_wallet_registry(["tsar3test"])
    mock_store.assert_called()

def test_encrypt_decrypt_wallet_file():
    data = {"wallets": {"tsar1": {}}}
    pwd = "masterpassword"
    enc = data_security.encrypt_wallet_file(data, pwd)
    dec = data_security.decrypt_wallet_file(enc, pwd)
    assert dec == data

@patch("kremlin.security.data_security._write_atomic")
@patch("kremlin.security.data_security._read_file_bytes")
@patch("os.path.exists", return_value=True)
def test_backup_restore_keystore(mock_exists, mock_read, mock_write):
    data = {"version": 2, "wallets": {"tsar1": {}}}
    pwd = "pwd"
    enc = data_security.encrypt_wallet_file(data, pwd)
    
    mock_read.return_value = enc
    ks_bytes = data_security.get_encrypted_keystore_bytes()
    assert ks_bytes == enc
    
    data_security.restore_keystore_bytes(enc, pwd)
    mock_write.assert_called()

@patch("kremlin.security.data_security.load_keystore")
@patch("kremlin.security.data_security.save_keystore")
def test_delete_address_from_keystore(mock_save, mock_load):
    mock_load.return_value = {"wallets": {"tsar1": {}}, "default": "tsar1"}
    assert data_security.delete_address_from_keystore("tsar1", "pwd") == True
    mock_save.assert_called()
    assert data_security.delete_address_from_keystore("tsar2", "pwd") == False

@patch("kremlin.security.data_security.Tx")
def test_sign_prepared_tx(mock_tx):
    mock_instance = MagicMock()
    mock_tx.from_dict.return_value = mock_instance
    mock_instance.inputs = [1]
    mock_instance.sign_input.return_value = True
    
    unsigned_tx_dict = {"test": 1}
    inputs_meta = [{"script_pubkey": "00", "amount": 100}]
    privkey_hex = "01"*32
    
    tx = data_security.Wallet.sign_prepared_tx(unsigned_tx_dict, inputs_meta, privkey_hex)
    assert tx == mock_instance
    mock_instance.sign_input.assert_called_once()
    mock_instance.set_fee_from_input_amounts.assert_called_once()

@patch("kremlin.security.data_security.pubkey_from_privhex", return_value=b"pub")
@patch("kremlin.security.data_security.pubkey_to_tsar_address", return_value="tsar1")
def test_wallet_from_private_key_hex(mock_addr, mock_pub):
    res = data_security.Wallet.from_private_key_hex("01"*32)
    assert res["address"] == "tsar1"
    assert res["private_key"] == "01"*32

def test_keystore_real_load_save(tmp_path):
    with patch("kremlin.security.data_security.WALLET_FILE", str(tmp_path / "wallet.enc")):
        ks = data_security.load_keystore("pwd")
        assert ks["version"] == data_security.KEYSTORE_VERSION
        
        data_security.save_keystore(ks, "pwd")
        ks_loaded = data_security.load_keystore("pwd")
        assert ks_loaded["version"] == data_security.KEYSTORE_VERSION

        raw = data_security._read_file_bytes(str(tmp_path / "wallet.enc"))
        assert len(raw) > 0

        data_security._write_atomic_json(str(tmp_path / "atomic.json"), {"atomic": True})
        assert os.path.exists(tmp_path / "atomic.json")

def test_add_privkey_real_keystore(tmp_path):
    with patch("kremlin.security.data_security.WALLET_FILE", str(tmp_path / "wallet.enc")):
        priv = "01"*32
        addr = data_security.add_privkey_to_keystore(priv, "pwd")
        assert addr is not None
        addr2 = data_security.add_privkey_to_keystore(priv, "pwd")
        assert addr == addr2
        
        addrs = data_security.list_addresses_in_keystore("pwd")
        assert addr in addrs


def test_create_new_address_with_cached_password():
    from kremlin.tab_ui.wallet_tab import WalletsMixin
    class DummyWalletTab(WalletsMixin):
        def __init__(self):
            self.wallets = ["tsar1existing"]
            self.root = MagicMock()
            self._ks_pwd_cache = ("TestPass123!", 9999999999.0)
            self._toast = MagicMock()
            self._show_mnemonic_dialog = MagicMock()
            self._wallets_update_mode = MagicMock()
            self._notify_balance_refresh = MagicMock()
            self.reload_addresses = MagicMock()
            self._render_wallet_list = MagicMock()

    with patch("kremlin.tab_ui.wallet_tab.Wallet.create") as mock_create, \
         patch("kremlin.tab_ui.wallet_tab.save_registry"):
        mock_create.return_value = ("tsar1newaddr", "word " * 12)
        tab = DummyWalletTab()
        tab.create_new_address()

        mock_create.assert_called_once_with("TestPass123!")
        assert "tsar1newaddr" in tab.wallets
        tab._toast.assert_called_once_with("Address created", kind="info")
        tab._show_mnemonic_dialog.assert_called_once_with("tsar1newaddr", "word " * 12)


def test_create_new_address_wrong_password():
    from kremlin.tab_ui.wallet_tab import WalletsMixin
    class DummyWalletTab(WalletsMixin):
        def __init__(self):
            self.wallets = ["tsar1existing"]
            self.root = MagicMock()
            self._ks_pwd_cache = None
            self._toast = MagicMock()
            self._show_mnemonic_dialog = MagicMock()
            self._wallets_update_mode = MagicMock()
            self._notify_balance_refresh = MagicMock()
            self.reload_addresses = MagicMock()
            self._render_wallet_list = MagicMock()

    with patch("kremlin.tab_ui.wallet_tab.Wallet.create") as mock_create, \
         patch("kremlin.tab_ui.wallet_tab.messagebox.showerror") as mock_error:
        mock_create.side_effect = ValueError("Invalid password or corrupted data")
        tab = DummyWalletTab()
        tab._ask_password = MagicMock(return_value="WrongPass!")

        tab.create_new_address()

        assert tab._ks_pwd_cache is None
        mock_error.assert_called_once()
        assert "tsar1newaddr" not in tab.wallets


def test_create_wallet_handles_failure():
    from kremlin.tab_ui.wallet_tab import WalletsMixin
    class DummyWalletTab(WalletsMixin):
        def __init__(self):
            self.wallets = []
            self.root = MagicMock()
            self.bg = "#000"
            self.panel_bg = "#111"
            self.fg = "#fff"
            self.muted = "#888"
            self.accent = "#f00"
            self._ks_pwd_cache = None
            self._toast = MagicMock()
            self._show_mnemonic_dialog = MagicMock()
            self._wallets_update_mode = MagicMock()
            self._notify_balance_refresh = MagicMock()
            self.reload_addresses = MagicMock()
            self._render_wallet_list = MagicMock()

    with patch("kremlin.tab_ui.wallet_tab.CreateWalletDialog") as mock_dlg_cls, \
         patch("kremlin.tab_ui.wallet_tab.Wallet.create") as mock_create, \
         patch("kremlin.tab_ui.wallet_tab.messagebox.showerror") as mock_error:
        mock_dlg = MagicMock()
        mock_dlg.result_password = "BadPassword"
        mock_dlg_cls.return_value = mock_dlg
        mock_create.side_effect = ValueError("Weak password")

        tab = DummyWalletTab()
        tab.create_wallet()

        mock_error.assert_called_once()


def test_mnemonic_storage_and_unlock_real_keystore(tmp_path):
    with patch("kremlin.security.data_security.WALLET_FILE", str(tmp_path / "wallet.enc")):
        pwd = "StrongPass123!@#"
        addr, mnemonic = data_security.Wallet.create(pwd)
        assert addr is not None
        assert len(mnemonic.split()) == 12

        unlocked = data_security.Wallet.unlock(pwd, addr)
        assert unlocked["address"] == addr
        assert unlocked["mnemonic"] == mnemonic

        # Test create from mnemonic
        mnemo_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        addr2 = data_security.Wallet.create_from_mnemonic(mnemo_phrase, pwd)
        unlocked2 = data_security.Wallet.unlock(pwd, addr2)
        assert unlocked2["mnemonic"] == mnemo_phrase

        # Test create from private key hex (no mnemonic)
        priv = "01" * 32
        addr3 = data_security.Wallet.create_from_privkey_hex(priv, pwd)
        unlocked3 = data_security.Wallet.unlock(pwd, addr3)
        assert unlocked3["mnemonic"] == ""


def test_toast_methods():
    from kremlin.tab_ui.wallet_tab import WalletsMixin
    with patch("kremlin.tab_ui.wallet_tab.show_toast") as mock_show_toast:
        tab = WalletsMixin()
        tab._toast("Test toast", ms=1200, kind="info")
        mock_show_toast.assert_called_once_with(tab, "Test toast", ms=1200, kind="info")


def test_menu_show_mnemonic_success():
    from kremlin.tab_ui.wallet_tab import WalletsMixin
    class DummyWalletTab(WalletsMixin):
        def __init__(self):
            self.root = MagicMock()
            self.bg = "#000"
            self.panel_bg = "#111"
            self.fg = "#fff"
            self.muted = "#888"
            self.accent = "#f00"
            self._ask_password = MagicMock(return_value="pwd")

    tab = DummyWalletTab()
    with patch("kremlin.tab_ui.wallet_tab.Wallet.unlock") as mock_unlock, \
         patch("kremlin.tab_ui.wallet_tab.tk.Toplevel") as mock_toplevel, \
         patch("kremlin.tab_ui.wallet_tab.tk.StringVar"), \
         patch("kremlin.tab_ui.wallet_tab.center_window"):
        mock_unlock.return_value = {"mnemonic": "word " * 12, "private_key": "01"*32}
        mock_dlg = MagicMock()
        mock_toplevel.return_value = mock_dlg
        tab._menu_show_mnemonic("tsar1test")

        mock_unlock.assert_called_once_with("pwd", "tsar1test")
        mock_toplevel.assert_called_once()


def test_menu_show_mnemonic_not_available():
    from kremlin.tab_ui.wallet_tab import WalletsMixin
    class DummyWalletTab(WalletsMixin):
        def __init__(self):
            self.root = MagicMock()
            self._ask_password = MagicMock(return_value="pwd")

    tab = DummyWalletTab()
    with patch("kremlin.tab_ui.wallet_tab.Wallet.unlock") as mock_unlock, \
         patch("kremlin.tab_ui.wallet_tab.messagebox.showwarning") as mock_warn:
        mock_unlock.return_value = {"mnemonic": "", "private_key": "01"*32}
        tab._menu_show_mnemonic("tsar1test")

        mock_unlock.assert_called_once_with("pwd", "tsar1test")
        mock_warn.assert_called_once()

