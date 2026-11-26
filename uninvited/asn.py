"""Which network operator (ASN) and country an IPv4 address belongs to, from the offline
iptoasn.com table (ip2asn-v4-u32.tsv.gz, public domain). Looked up once, at enrolment,
because no raw address is kept afterwards. Only the ASN number and country are recorded.
"""
import bisect
import gzip
import ipaddress
from array import array


class AsnTable:
    def __init__(self, path):
        self.starts, self.ends, self.asns, self.countries = array("I"), array("I"), array("I"), []
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 4:
                    continue
                try:
                    start, end, asn = int(parts[0]), int(parts[1]), int(parts[2])
                except ValueError:
                    continue
                if not (0 <= start <= end < 2**32 and 0 <= asn < 2**32):
                    continue
                if self.starts and start < self.starts[-1]:
                    raise ValueError("ASN table is not sorted")
                self.starts.append(start)
                self.ends.append(end)
                self.asns.append(asn)
                code = parts[3].strip()
                self.countries.append(code if len(code) == 2 and code.isalpha() else "")
        if not self.starts:
            raise ValueError("ASN table is empty")

    def __call__(self, ip):
        """(asn, country) for the address; (0, "") if it is in no routed range."""
        n = int(ipaddress.IPv4Address(ip))
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and n <= self.ends[i] and self.asns[i]:
            return self.asns[i], self.countries[i]
        return 0, ""


def no_table(ip):
    return 0, ""
