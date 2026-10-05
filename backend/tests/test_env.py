import pytest

from app.services import deliverability
from app.utils.env import sanitize_env


def test_comment_only_values_become_empty():
    env = {'RBL_RESOLVERS': '# your own DNS resolver for blocklist checks (Spamhaus refuses public resolvers)',
           'ALERT_WEBHOOK_URL': '                  # Slack or any generic JSON webhook'}
    changed = sanitize_env(env)
    assert env == {'RBL_RESOLVERS': '', 'ALERT_WEBHOOK_URL': ''}
    assert sorted(changed) == ['ALERT_WEBHOOK_URL', 'RBL_RESOLVERS']


def test_trailing_comments_are_stripped_but_the_value_is_kept():
    env = {'CT_API_URL': 'https://crt.sh/          # Certificate Transparency search service',
           'STATUS_PAGE_TITLE': 'Certificate status # heading of the public status page',
           'ACME_DNS_RESOLVERS': '1.1.1.1,8.8.8.8  # resolvers'}
    sanitize_env(env)
    assert env == {'CT_API_URL': 'https://crt.sh/', 'STATUS_PAGE_TITLE': 'Certificate status',
                   'ACME_DNS_RESOLVERS': '1.1.1.1,8.8.8.8'}


def test_values_without_comments_and_url_fragments_are_untouched():
    env = {'APP_URL': 'https://tools.example.com/#/status', 'RBL_LISTS': 'a.example,b.example', 'SMTP_PORT': '587'}
    assert sanitize_env(env) == []
    assert env['APP_URL'] == 'https://tools.example.com/#/status'


def test_secrets_and_unrelated_variables_are_never_touched():
    env = {'SMTP_PASSWORD': 'pa ss #word', 'ADMIN_TOKEN': 'a #b', 'SECRET_KEY': 'x #y', 'PS1': 'user # ', 'OTHER': 'v # c'}
    before = dict(env)
    assert sanitize_env(env) == []
    assert env == before


def test_invalid_resolver_entries_are_ignored_instead_of_breaking_dns(monkeypatch):
    monkeypatch.setenv('RBL_RESOLVERS', '# your own DNS resolver')
    r = deliverability._resolver()
    assert all(ns != '# your own DNS resolver' for ns in r.nameservers)
    monkeypatch.setenv('RBL_RESOLVERS', '192.0.2.53, not-an-ip ,2001:db8::53')
    assert deliverability._resolver().nameservers == ['192.0.2.53', '2001:db8::53']
