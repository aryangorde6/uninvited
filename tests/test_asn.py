import gzip
import ipaddress

from uninvited.asn import AsnTable

ROWS = [("1.0.0.0", "1.0.0.255", 13335, "US"), ("81.2.69.0", "81.2.69.255", 20712, "GB"),
        ("81.2.70.0", "81.2.70.255", 0, "None")]


def write_table(path, rows, extra=""):
    with gzip.open(path, "wt") as f:
        f.write(extra)
        for a, b, asn, cc in rows:
            f.write(f"{int(ipaddress.IPv4Address(a))}\t{int(ipaddress.IPv4Address(b))}\t{asn}\t{cc}\tSome Name\n")


def test_lookup_inside_outside_and_unrouted(tmp_path):
    p = tmp_path / "t.tsv.gz"
    write_table(p, ROWS, extra="garbage line\n\n")
    t = AsnTable(p)
    assert t("81.2.69.142") == (20712, "GB")
    assert t("1.0.0.0") == (13335, "US") and t("1.0.0.255") == (13335, "US")
    assert t("81.2.70.5") == (0, "")          # listed but not routed
    assert t("9.9.9.9") == (0, "")            # in no range
    assert t("0.0.0.1") == (0, "")            # before the first range
