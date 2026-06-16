"""Date conversion tests from the spec's worked examples (§3.3, §3.4.2)."""

from datetime import date

from twoddoc import dates


def test_emission_signature_dates_c40():
    # §3.3.1 example: emission 0E84 = 5 Mar 2010, signature 0E8A = 11 Mar 2010
    assert dates.days_since_2000_to_date("0E84") == date(2010, 3, 5)
    assert dates.days_since_2000_to_date("0E8A") == date(2010, 3, 11)


def test_undated_sentinel():
    assert dates.days_since_2000_to_date("FFFF") is None


def test_roundtrip_days():
    d = date(2011, 12, 31)
    n = dates.date_to_days_since_2000(d)
    assert dates.days_since_2000_to_date(n) == d


def test_binary_date():
    # §3.4.2: 27 June 1969 -> 06271969 -> 0x5FB3E1
    assert dates.binary_date_to_date(bytes.fromhex("5FB3E1")) == date(1969, 6, 27)
    assert dates.date_to_binary_date(date(1969, 6, 27)) == bytes.fromhex("5FB3E1")


def test_binary_date_undated():
    assert dates.binary_date_to_date(bytes.fromhex("FFFFFF")) is None


def test_parse_time():
    assert dates.parse_hhmmss("133759") == "13:37:59"
