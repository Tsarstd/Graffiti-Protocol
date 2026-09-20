# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

from web.Backend.src.core.build_history_book import HistoryBookGenerator

try:
    import tsarcore_native as _real_tsarcore
    mock_tsarcore = MagicMock(wraps=_real_tsarcore)
except Exception:
    mock_tsarcore = MagicMock()
mock_tsarcore.generate_qr_code.return_value = b"mocked_qr"
mock_tsarcore.format_tsar_amount.return_value = "1,000 TSAR"
mock_tsarcore.split_amount_parts.return_value = ("1", "000", " TSAR")
mock_tsarcore.format_history_direction.return_value = "Incoming"

class MockRowData:
    def __init__(self, is_amount=False, amount_value=None):
        self.y_position = 100
        self.label = "Label"
        self.label_color = (0, 0, 0)
        self.value = "Value"
        self.value_color = (0, 0, 0)
        self.amount_value = amount_value
        self.line_color = (0, 0, 0)

mock_tsarcore.draw_table_row_data.side_effect = lambda y_position, label, value, is_amount, amount_value, page_width: MockRowData(is_amount, amount_value)

def mock_paginate_history(history, items_per_page):
    if not history:
        return []
    pages = []
    current_page = []
    for item in history:
        if len(current_page) == items_per_page:
            pages.push(current_page)
            current_page = []
        current_page.append(item)
    if current_page:
        pages.append(current_page)
    return pages

mock_tsarcore.paginate_history.side_effect = mock_paginate_history

class MockAddressGridData:
    def __init__(self):
        self.grid = [["t", "s", "a", "r"]]
        self.highlight_positions = [(1, 0)]
        self.char_positions = [('t', 200, 165, (3, 95, 166))]
        self.address_type = "P2WPKH"
        self.label_type = "Citizen Address"
        self.total_height = 80.0

mock_tsarcore.draw_address_grid_data.return_value = MockAddressGridData()

sys.modules['tsarcore_native'] = mock_tsarcore

@pytest.fixture
def temp_dir(tmp_path):
    return str(tmp_path)

@pytest.fixture
def mock_image():
    with patch('web.Backend.src.core.build_history_book.Image.open') as mock_open:
        mock_img = MagicMock()
        mock_img.mode = 'RGB'
        mock_img.size = (800, 1200)
        mock_img.width = 800
        mock_img.height = 1200
        mock_img.copy.return_value = mock_img
        mock_img.convert.return_value = mock_img
        mock_img.rotate.return_value = mock_img
        mock_img.resize.return_value = mock_img
        mock_img.save = MagicMock()
        mock_open.return_value = mock_img
        yield mock_open, mock_img

@pytest.fixture
def mock_font():
    with patch('web.Backend.src.core.build_history_book.ImageFont.truetype') as mock_tt, \
         patch('web.Backend.src.core.build_history_book.ImageFont.load_default') as mock_ld:
        mock_font_inst = MagicMock()
        mock_tt.return_value = mock_font_inst
        mock_ld.return_value = mock_font_inst
        yield mock_tt, mock_ld, mock_font_inst

@pytest.fixture
def mock_draw():
    with patch('web.Backend.src.core.build_history_book.ImageDraw.Draw') as mock_dr:
        mock_draw_inst = MagicMock()
        mock_draw_inst.textlength.return_value = 10
        mock_dr.return_value = mock_draw_inst
        yield mock_dr, mock_draw_inst

def test_init_caches_exist(temp_dir, mock_image, mock_font):
    with patch('os.path.exists', return_value=True):
        gen = HistoryBookGenerator(temp_dir)
        assert len(gen._font_cache) == 4

def test_generate_history_book_invalid_data(temp_dir):
    gen = HistoryBookGenerator(temp_dir)
    success, msg, data = gen.generate_history_book({})
    assert success is False
    assert "Invalid history data" in msg

def test_generate_history_book_success(temp_dir, mock_image, mock_font, mock_draw):
    mock_open, mock_img = mock_image
    gen = HistoryBookGenerator(temp_dir)
    
    tx_data = {
        'address': 'tsar1234567890abcdef',
        'balance': 1000,
        'total_txs': 2,
        'history': [
            {'txid': 'tx1', 'timestamp': 1000, 'amount': 10, 'direction': 'in', 'status': 'confirmed', 'height': 12345, 'confirmations': 10, 'from': 'coinbase'},
            {'txid': 'tx2', 'timestamp': 2000, 'amount': 20, 'direction': 'out', 'status': 'unconfirmed', 'height': None, 'confirmations': 0, 'to': 'tsar1abc'}
        ]
    }
    
    with patch('os.path.join', return_value=os.path.join(temp_dir, 'history.pdf')):
        success, path, pdf_bytes = gen.generate_history_book(tx_data)
        assert success is True
        assert pdf_bytes is not None

def test_generate_history_book_base64_success(temp_dir):
    gen = HistoryBookGenerator(temp_dir)
    tx_data = {'address': 'tsar123'}
    
    with patch.object(gen, 'generate_history_book', return_value=(True, 'path', b"pdf_data")):
        result = gen.generate_history_book_base64(tx_data)
        assert result['status'] == 'success'
        assert result['data_url'].startswith('data:application/pdf;base64,')

def test_generate_history_book_base64_fail(temp_dir):
    gen = HistoryBookGenerator(temp_dir)
    tx_data = {'address': 'tsar123'}
    
    with patch.object(gen, 'generate_history_book', return_value=(False, 'error msg', None)):
        result = gen.generate_history_book_base64(tx_data)
        assert result['status'] == 'error'
        assert result['message'] == 'error msg'

def test_generate_history_book_exception(temp_dir):
    gen = HistoryBookGenerator(temp_dir)
    with patch('web.Backend.src.core.build_history_book.Image.open', side_effect=Exception("Force fail")):
        success, msg, data = gen.generate_history_book({'address': 'tsar123', 'history': []})
        assert success is False
        assert "Error:" in msg

def test_generate_history_book_p2wsh_address(temp_dir, mock_image, mock_font, mock_draw):
    mock_open, mock_img = mock_image
    gen = HistoryBookGenerator(temp_dir)
    
    tx_data = {
        'address': 'tsar1qhxm6436vjz952t5d8nr27w9ykc25qrt55xj3de5zt8trtfkgx0pqzq9vkp',
        'balance': 1000,
        'history': []
    }
    
    with patch('os.path.join', return_value=os.path.join(temp_dir, 'history.pdf')):
        success, path, pdf_bytes = gen.generate_history_book(tx_data)
        assert success is True
        assert pdf_bytes is not None

def test_generate_history_book_p2wpkh_address(temp_dir, mock_image, mock_font, mock_draw):
    mock_open, mock_img = mock_image
    gen = HistoryBookGenerator(temp_dir)
    
    tx_data = {
        'address': 'tsar1qakf6mle606amn7xumvz4k6yu6cz0mxq6pe5qwr',
        'balance': 1000,
        'history': []
    }
    
    with patch('os.path.join', return_value=os.path.join(temp_dir, 'history.pdf')):
        success, path, pdf_bytes = gen.generate_history_book(tx_data)
        assert success is True
        assert pdf_bytes is not None

