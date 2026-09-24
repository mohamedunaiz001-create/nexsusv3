import pytest

from app.tools.gateway import ToolGatewayError, _validate_indicator


@pytest.mark.parametrize(
    ("action", "value"),
    [
        ("hash.lookup", "a" * 32),
        ("hash.lookup", "b" * 40),
        ("hash.lookup", "c" * 64),
        ("ip.lookup", "8.8.8.8"),
        ("ip.lookup", "2001:db8::1"),
        ("domain.lookup", "example.com"),
        ("url.lookup", "https://example.com/path"),
    ],
)
def test_valid_indicator_shapes_are_accepted(action, value):
    _validate_indicator(action, value)


@pytest.mark.parametrize(
    ("action", "value"),
    [
        ("hash.lookup", "not-a-hash"),
        ("ip.lookup", "999.1.1.1"),
        ("domain.lookup", "not a domain"),
        ("url.lookup", "javascript:alert(1)"),
        ("url.lookup", "example.com"),
    ],
)
def test_invalid_indicator_shapes_are_rejected(action, value):
    with pytest.raises(ToolGatewayError) as error:
        _validate_indicator(action, value)

    assert error.value.code == "INVALID_INDICATOR"


def test_unknown_actions_are_rejected():
    with pytest.raises(ToolGatewayError) as error:
        _validate_indicator("unknown.lookup", "example.com")

    assert error.value.code == "UNSUPPORTED_ACTION"