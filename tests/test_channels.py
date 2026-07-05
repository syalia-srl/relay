# tests/test_channels.py
from inbox_relay.channels import ChannelStore

def test_create_and_get():
    store = ChannelStore()
    ch = store.create()
    assert store.get(ch.channel_id) is ch

def test_get_by_token_mobile():
    store = ChannelStore()
    ch = store.create()
    result = store.get_by_token(ch.token_mobile)
    assert result is not None
    got_ch, side = result
    assert got_ch is ch
    assert side == "mobile"

def test_get_by_token_bridge():
    store = ChannelStore()
    ch = store.create()
    _, side = store.get_by_token(ch.token_bridge)
    assert side == "bridge"

def test_get_by_unknown_token():
    store = ChannelStore()
    assert store.get_by_token("bad") is None

def test_remove():
    store = ChannelStore()
    ch = store.create()
    store.remove(ch.channel_id)
    assert store.get(ch.channel_id) is None
    assert store.get_by_token(ch.token_mobile) is None

def test_other_side():
    store = ChannelStore()
    ch = store.create()
    assert ch.other_side("mobile") == "bridge"
    assert ch.other_side("bridge") == "mobile"
