# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Tsar Studio
# Part of TsarChain — see LICENSE

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

from web.Backend.src.core.build_receipt import PaymentReceiptGenerator

try:
    import tsarcore_native as _real_tsarcore
    mock_tsarcore = MagicMock(wraps=_real_tsarcore)
except Exception:
    mock_tsarcore = MagicMock()
mock_tsarcore.generate_qr_code.return_value = b"mocked_qr"
mock_tsarcore.format_tsar_amount.return_value = "1,000 TSAR"
mock_tsarcore.split_amount_parts.return_value = ("1", "000", " TSAR")
mock_tsarcore.truncate_text.return_value = "truncated"

class MockGridData:
    def __init__(self):
        self.char_positions = [('A', 0, 0, (0, 0, 0))]
        self.line_height = 10
mock_tsarcore.draw_txid_grid_data.return_value = MockGridData()

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

mock_tsarcore.pool_address.return_value = "mock_pool_address"
sys.modules['tsarcore_native'] = mock_tsarcore

@pytest.fixture
def temp_dir(tmp_path):
    return str(tmp_path)

@pytest.fixture
def reset_caches():
    PaymentReceiptGenerator._template_cache = None
    PaymentReceiptGenerator._font_cache = {}
    PaymentReceiptGenerator._stamp_cache = {}
    PaymentReceiptGenerator._rotated_stamp_cache = {}
    PaymentReceiptGenerator._tx_sticker_cache = {}
    yield
    PaymentReceiptGenerator._template_cache = None
    PaymentReceiptGenerator._font_cache = {}
    PaymentReceiptGenerator._stamp_cache = {}
    PaymentReceiptGenerator._rotated_stamp_cache = {}
    PaymentReceiptGenerator._tx_sticker_cache = {}

@pytest.fixture
def mock_image():
    with patch('web.Backend.src.core.build_receipt.Image.open') as mock_open:
        mock_img = MagicMock()
        mock_img.mode = 'RGB'
        mock_img.size = (800, 1200)
        mock_img.width = 800
        mock_img.height = 1200
        mock_img.copy.return_value = mock_img
        mock_img.convert.return_value = mock_img
        mock_img.rotate.return_value = mock_img
        mock_img.resize.return_value = mock_img
        mock_open.return_value = mock_img
        yield mock_open, mock_img

@pytest.fixture
def mock_font():
    with patch('web.Backend.src.core.build_receipt.ImageFont.truetype') as mock_tt, \
         patch('web.Backend.src.core.build_receipt.ImageFont.load_default') as mock_ld:
        mock_font_inst = MagicMock()
        mock_tt.return_value = mock_font_inst
        mock_ld.return_value = mock_font_inst
        yield mock_tt, mock_ld, mock_font_inst

@pytest.fixture
def mock_draw():
    with patch('web.Backend.src.core.build_receipt.ImageDraw.Draw') as mock_dr:
        mock_draw_inst = MagicMock()
        mock_draw_inst.textlength.return_value = 10
        mock_dr.return_value = mock_draw_inst
        yield mock_dr, mock_draw_inst

def test_init_and_caches_exist(temp_dir, reset_caches, mock_image, mock_font):
    mock_open, mock_img = mock_image
    
    with patch('os.path.exists', return_value=True):
        gen = PaymentReceiptGenerator(temp_dir)
        
    assert PaymentReceiptGenerator._template_cache is not None
    assert len(PaymentReceiptGenerator._font_cache) == 4
    assert len(PaymentReceiptGenerator._tx_sticker_cache) == 5

def test_init_and_caches_not_exist(temp_dir, reset_caches, mock_image, mock_font):
    mock_open, mock_img = mock_image
    
    with patch('os.path.exists', return_value=False), \
         patch('web.Backend.src.core.build_receipt.Image.new') as mock_new:
        mock_new.return_value = mock_img
        gen = PaymentReceiptGenerator(temp_dir)
        
    assert PaymentReceiptGenerator._template_cache is not None
    assert len(PaymentReceiptGenerator._font_cache) == 4
    for k, v in PaymentReceiptGenerator._tx_sticker_cache.items():
        assert v is None

def test_ensure_font_cache_exception(temp_dir, reset_caches):
    with patch('os.path.exists', return_value=True), \
         patch('web.Backend.src.core.build_receipt.ImageFont.truetype', side_effect=Exception("Font error")), \
         patch('web.Backend.src.core.build_receipt.ImageFont.load_default') as mock_ld:
        
        gen = PaymentReceiptGenerator(temp_dir)
        assert mock_ld.call_count == 4

def test_get_stamp(temp_dir, reset_caches, mock_image):
    with patch('os.path.exists', return_value=True):
        gen = PaymentReceiptGenerator(temp_dir)
        stamp = gen._get_stamp('confirmed')
        assert stamp is not None
        assert 'original_confirmed' in gen._stamp_cache
        
        # Test cache hit
        stamp2 = gen._get_stamp('confirmed')
        assert stamp is stamp2
        
        stamp_unconf = gen._get_stamp('unconfirmed')
        assert stamp_unconf is not None

def test_get_rotated_stamp(temp_dir, reset_caches, mock_image):
    with patch('os.path.exists', return_value=True):
        gen = PaymentReceiptGenerator(temp_dir)
        rotated = gen._get_rotated_stamp('confirmed')
        assert rotated is not None
        assert getattr(rotated, 'offset_x', None) is not None
        assert getattr(rotated, 'offset_y', None) is not None

def test_determine_tx_type(temp_dir, reset_caches):
    gen = PaymentReceiptGenerator(temp_dir)
    assert gen._determine_tx_type({'is_coinbase': True}) == 'coinbase'
    assert gen._determine_tx_type({'outputs': [{'event': 'POST'}]}) == 'post'
    assert gen._determine_tx_type({'outputs': [{'event': 'COMMENT'}]}) == 'comment'
    assert gen._determine_tx_type({'outputs': [{'event': 'PAYOUT'}]}) == 'payout'
    assert gen._determine_tx_type({'outputs': [{'event': 'OTHER'}]}) == 'regular'
    assert gen._determine_tx_type({'outputs': []}) == 'regular'

def test_qr_code(temp_dir, reset_caches):
    gen = PaymentReceiptGenerator(temp_dir)
    with patch('web.Backend.src.core.build_receipt.Image.open') as mock_open:
        gen._qr_code("txid")
        mock_open.assert_called_once()

def test_generate_receipt_invalid_data(temp_dir, reset_caches):
    gen = PaymentReceiptGenerator(temp_dir)
    success, msg, data = gen.generate_receipt({})
    assert success is False
    assert "Invalid" in msg

def test_generate_receipt_unconfirmed(temp_dir, reset_caches, mock_image, mock_font, mock_draw):
    mock_open, mock_img = mock_image
    gen = PaymentReceiptGenerator(temp_dir)
    
    tx_data = {
        'txid': '12345',
        'status': 'unconfirmed',
        'timestamp': 0,
        'inputs': [{'address': 'addr1', 'amount': 100}],
        'outputs': [{'address': 'addr2', 'amount': 90}]
    }
    
    with patch('os.path.join', return_value=os.path.join(temp_dir, '12345.jpg')):
        success, path, img_bytes = gen.generate_receipt(tx_data)
        assert success is True
        assert img_bytes is not None

def test_generate_receipt_coinbase(temp_dir, reset_caches, mock_image, mock_font, mock_draw):
    mock_open, mock_img = mock_image
    gen = PaymentReceiptGenerator(temp_dir)
    
    tx_data = {
        'txid': '12345',
        'status': 'confirmed',
        'timestamp': 1000000,
        'height': 123,
        'confirmations': 10,
        'is_coinbase': True,
        'inputs': [],
        'outputs': [{'address': 'miner_addr', 'amount': 500}],
        'bonus': 100
    }
    
    with patch('os.path.join', return_value=os.path.join(temp_dir, '12345.jpg')):
        success, path, img_bytes = gen.generate_receipt(tx_data)
        assert success is True

def test_generate_receipt_regular(temp_dir, reset_caches, mock_image, mock_font, mock_draw):
    mock_open, mock_img = mock_image
    gen = PaymentReceiptGenerator(temp_dir)
    
    tx_data = {
        'txid': '12345',
        'status': 'confirmed',
        'timestamp': 1000000,
        'fee': 10,
        'inputs': [{'address': 'addr1', 'amount': 1000}],
        'outputs': [
            {'address': 'addr2', 'amount': 500},
            {'address': 'addr1', 'amount': 490}, # change
            {'amount': 0} # opret
        ]
    }
    
    with patch('os.path.join', return_value=os.path.join(temp_dir, '12345.jpg')):
        success, path, img_bytes = gen.generate_receipt(tx_data)
        assert success is True

def test_generate_receipt_base64_success(temp_dir, reset_caches, mock_image, mock_font, mock_draw):
    mock_open, mock_img = mock_image
    gen = PaymentReceiptGenerator(temp_dir)
    tx_data = {'txid': '12345'}
    
    with patch.object(gen, 'generate_receipt', return_value=(True, 'path', b"image_data")):
        result = gen.generate_receipt_base64(tx_data)
        assert result['status'] == 'success'
        assert result['data_url'].startswith('data:image/jpeg;base64,')

def test_generate_receipt_base64_fail(temp_dir, reset_caches):
    gen = PaymentReceiptGenerator(temp_dir)
    tx_data = {'txid': '12345'}
    
    with patch.object(gen, 'generate_receipt', return_value=(False, 'error msg', None)):
        result = gen.generate_receipt_base64(tx_data)
        assert result['status'] == 'error'
        assert result['message'] == 'error msg'

def test_generate_receipt_exception(temp_dir, reset_caches):
    gen = PaymentReceiptGenerator(temp_dir)
    with patch('web.Backend.src.core.build_receipt.Image.open', side_effect=Exception("Force fail")):
        success, msg, data = gen.generate_receipt({'txid': '123'})
        assert success is False
        assert "Error:" in msg