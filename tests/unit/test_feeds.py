import json

import pytest
import yaml

from app.core import feeds, vendors


def mispBlob(values):
    return {'content': [{'value': v} for v in values]}


# --- removeInvisibleCharacters ---

def test_remove_invisible_characters_strips_zero_width_space():
    assert feeds.removeInvisibleCharacters("ab‌cd") == "abcd"


def test_remove_invisible_characters_preserves_tab_newline_cr():
    assert feeds.removeInvisibleCharacters("a\tb\nc\rd") == "a\tb\nc\rd"


def test_remove_invisible_characters_empty_string():
    assert feeds.removeInvisibleCharacters("") == ""


def test_remove_invisible_characters_unchanged_when_clean():
    assert feeds.removeInvisibleCharacters("clean-value") == "clean-value"


# --- mispDataParsingSimple ---

def test_parsing_ipv4_extracts_and_dedupes():
    blob = mispBlob(["1.2.3.4", "1.2.3.4", "not-an-ip", "5.6.7.8"])
    result = feeds.mispDataParsingSimple(blob, "ipv4")
    assert result == ["1.2.3.4", "5.6.7.8"]


def test_parsing_ipv4_excludes_cidr_notation():
    blob = mispBlob(["10.0.0.0/24", "1.2.3.4"])
    result = feeds.mispDataParsingSimple(blob, "ipv4")
    assert result == ["1.2.3.4"]


def test_parsing_ipv4ext_expands_cidr():
    blob = mispBlob(["192.0.2.0/30"])
    result = feeds.mispDataParsingSimple(blob, "ipv4ext")
    assert result == ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"]


def test_parsing_ipv6_validates_address():
    blob = mispBlob(["2001:db8::1", "not-an-ipv6"])
    result = feeds.mispDataParsingSimple(blob, "ipv6")
    assert result == ["2001:db8::1"]


def test_parsing_domain():
    blob = mispBlob(["example.com", "not a domain"])
    result = feeds.mispDataParsingSimple(blob, "domain")
    assert result == ["example.com"]


def test_parsing_file_md5():
    blob = mispBlob(["d41d8cd98f00b204e9800998ecf8427e", "too-short"])
    result = feeds.mispDataParsingSimple(blob, "file-md5")
    assert result == ["d41d8cd98f00b204e9800998ecf8427e"]


def test_parsing_vulnerability_cve():
    blob = mispBlob(["CVE-2023-1234", "not-a-cve"])
    result = feeds.mispDataParsingSimple(blob, "vulnerability")
    assert result == ["CVE-2023-1234"]


def test_parsing_email_address():
    blob = mispBlob(["user@example.com", "not-an-email"])
    result = feeds.mispDataParsingSimple(blob, "email-address")
    assert result == ["user@example.com"]


def test_parsing_strips_invisible_characters_before_matching():
    blob = mispBlob(["1.2.3.4​"])
    result = feeds.mispDataParsingSimple(blob, "ipv4")
    assert result == ["1.2.3.4"]


# --- feedDefineMISPSearch ---

def baseRequestData(**overrides):
    data = {
        'tagNames': {
            'falsepositive': 'tag:incident-classification=false-positive',
            'incident': 'tag:incident-classification=incident',
            'block': 'tag:incident-classification=block',
        },
        'dataTypes': ['ip-src'],
        'ignore_to_ids': [],
        'timestamp': 1234567890,
    }
    data.update(overrides)
    return data


def test_feed_define_misp_search_incident_not_published():
    result = feeds.feedDefineMISPSearch('incident', baseRequestData())
    assert result['published'] is False
    assert result['to_ids'] is True
    assert 'tag:incident-classification=false-positive' in result['tags']
    assert 'tag:incident-classification=incident' in result['tags']


def test_feed_define_misp_search_block_is_published():
    result = feeds.feedDefineMISPSearch('block', baseRequestData())
    assert result['published'] is True


def test_feed_define_misp_search_42_ignores_warninglist():
    result = feeds.feedDefineMISPSearch('42', baseRequestData())
    assert result['enforceWarninglist'] is False


def test_feed_define_misp_search_falsepositive_uses_raw_tags():
    requestData = baseRequestData(tagNames=['tag:incident-classification=false-positive'])
    result = feeds.feedDefineMISPSearch('falsepositive', requestData)
    assert result['tags'] == ['tag:incident-classification=false-positive']
    assert result['published'] is False
    assert result['enforceWarninglist'] is False


def test_feed_define_misp_search_ignore_to_ids_for_matching_type():
    requestData = baseRequestData(dataTypes=['vulnerability'], ignore_to_ids=['vulnerability'])
    result = feeds.feedDefineMISPSearch('incident', requestData)
    assert result['to_ids'] is None


# --- organizationDefineMISPSearch ---

def test_organization_define_misp_search_sets_org():
    result = feeds.organizationDefineMISPSearch('some-uuid', baseRequestData())
    assert result['org'] == 'some-uuid'
    assert result['published'] is True


# --- getFeedNameToTag ---

def test_get_feed_name_to_tag_includes_standard_and_custom_feeds():
    result = feeds.getFeedNameToTag('mytag', {'cust1': ':incident-classification=cust1'})
    assert result['incident'] == 'mytag:incident-classification=incident'
    assert result['cust1'] == 'mytag:incident-classification=cust1'
    assert result['falsepositive'] == '!mytag:incident-classification=false-positive'


# --- formatFeedOutputData (cachingTime=0 to avoid touching memcached) ---

def test_format_feed_output_data_json():
    blob = mispBlob(["1.2.3.4"])
    result = feeds.formatFeedOutputData(blob, "json", "ipv4", 0, "cachekey")
    assert result['content_type'] == 'application/json'
    assert json.loads(result['content']) == ["1.2.3.4"]


def test_format_feed_output_data_txt():
    blob = mispBlob(["1.2.3.4", "5.6.7.8"])
    result = feeds.formatFeedOutputData(blob, "txt", "ipv4", 0, "cachekey")
    assert result['content'] == "1.2.3.4\r\n5.6.7.8"


def test_format_feed_output_data_yaml():
    blob = mispBlob(["1.2.3.4"])
    result = feeds.formatFeedOutputData(blob, "yaml", "ipv4", 0, "cachekey")
    assert yaml.safe_load(result['content']) == ["1.2.3.4"]


def test_format_feed_output_data_b64():
    blob = mispBlob(["1.2.3.4"])
    result = feeds.formatFeedOutputData(blob, "b64", "ipv4", 0, "cachekey")
    import base64
    assert base64.b64decode(result['content']).decode() == "1.2.3.4"


def test_format_feed_output_data_xml():
    blob = mispBlob(["1.2.3.4"])
    result = feeds.formatFeedOutputData(blob, "xml", "ipv4", 0, "cachekey")
    assert "<entry>1.2.3.4</entry>" in result['content']


# --- formatWarninglistOutputData ---

def test_format_warninglist_output_data_index_json():
    blob = {'content': {'Warninglists': [{'Warninglist': {'id': '1', 'name': 'test'}}]}}
    result = feeds.formatWarninglistOutputData(blob, "json")
    assert json.loads(result['content']) == [{'Warninglist': {'id': '1', 'name': 'test'}}]


def test_format_warninglist_output_data_entry_txt():
    blob = {'content': {'Warninglist': {'WarninglistEntry': [{'value': '1.2.3.4'}, {'value': '5.6.7.8'}]}}}
    result = feeds.formatWarninglistOutputData(blob, "txt")
    assert result['content'] == "1.2.3.4\r\n5.6.7.8\r\n"


# --- vendors.py (cachingTime=0 to avoid touching memcached) ---

def test_format_paloalto_strips_url_protocol():
    blob = mispBlob(["http://evil.example.com/path"])
    result = vendors.formatPaloaltoOutputData(blob, "url", 0, "cachekey")
    assert result['content'] == "evil.example.com/path"


def test_format_paloalto_leaves_non_url_data_untouched():
    blob = mispBlob(["1.2.3.4"])
    result = vendors.formatPaloaltoOutputData(blob, "ipv4", 0, "cachekey")
    assert result['content'] == "1.2.3.4"


def test_format_cisco_does_not_strip_protocol():
    blob = mispBlob(["http://evil.example.com/path"])
    result = vendors.formatCiscoOutputData(blob, "url", 0, "cachekey")
    assert result['content'] == "http://evil.example.com/path"
