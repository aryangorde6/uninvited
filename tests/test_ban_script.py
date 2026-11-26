import importlib.machinery
import importlib.util
import pathlib

import pytest

path = pathlib.Path(__file__).parent.parent / "fleet" / "uninvited-ban"
loader = importlib.machinery.SourceFileLoader("uninvited_ban", str(path))
spec = importlib.util.spec_from_loader("uninvited_ban", loader)
ban_script = importlib.util.module_from_spec(spec)
loader.exec_module(ban_script)


def test_valid_lines():
    assert ban_script.check("ban 81.2.69.142 600\n", set()) == ("81.2.69.142", 600)
    assert ban_script.check("ban 81.2.69.142 999999", set()) == ("81.2.69.142", 43200)


@pytest.mark.parametrize("line", [
    "ban 81.2.69.142 600; nft flush ruleset", "ban 81.2.69.142 -1", "ban 81.2.69.142 0",
    "ban 081.2.69.142 600", "ban 999.2.69.142 600", "unban 81.2.69.142", "ban 81.2.69.142",
    "ban  81.2.69.142 600", "ban 10.0.0.1 600", "ban 127.0.0.1 600", "ban 203.0.113.9 600",
    "ban 81.2.69.142 600\nban 81.2.69.143 600", "ban 2001:db8::1 600", "",
])
def test_refused_lines(line):
    with pytest.raises(ValueError):
        ban_script.check(line, set())


def test_never_ban_list():
    with pytest.raises(ValueError):
        ban_script.check("ban 81.2.69.142 600", {"81.2.69.142"})
