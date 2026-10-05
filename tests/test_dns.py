from styxrecon.dns import lookup


def test_dns_lookup():
    result = lookup("example.com")

    assert isinstance(result, dict)

    for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        assert record_type in result
        assert isinstance(result[record_type], list)
