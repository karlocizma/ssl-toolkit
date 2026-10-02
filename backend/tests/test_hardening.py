"""Regression tests for findings from code scanning."""
from unittest.mock import patch

import pytest

from app import create_app
from app.services.autodiscover import _safe_xml

ENTITY_BOMB = (
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>'
    '<x>&b;</x>'
)


def test_autodiscover_rejects_entity_declarations():
    assert _safe_xml(ENTITY_BOMB) is None


def test_unexpected_errors_do_not_leak_details():
    client = create_app().test_client()
    with patch('app.routes.ssl_routes.get_certificate_info', side_effect=RuntimeError('secret /srv/path')):
        response = client.post('/api/certificate/decode', json={'certificate': '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'})
    assert response.status_code == 500
    assert 'secret' not in response.get_data(as_text=True)
