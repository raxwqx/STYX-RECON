
import dns.resolver


RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
]


def lookup(domain: str) -> dict:
    results = {}

    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [answer.to_text() for answer in answers]
        except Exception:
            results[record_type] = []

    return results
