"""Tests for the HIBP API client."""
from unittest.mock import Mock, patch

import pytest

from src.breach_api import HaveIBeenPwnedAPI
from src.models import Breach


@pytest.fixture
def api():
    return HaveIBeenPwnedAPI(api_key="test_key")


@patch("requests.Session.get")
def test_get_breached_account_success(mock_get, api):
    """Test successfully fetching breaches for an email."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "Name": "TestBreach",
            "Title": "Test Breach",
            "Domain": "example.com",
            "BreachDate": "2023-01-01",
            "AddedDate": "2023-01-02T00:00:00Z",
            "PwnCount": 1000,
            "Description": "Test description",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
        }
    ]
    mock_get.return_value = mock_response

    breaches = api.get_breached_account("test@example.com")

    assert len(breaches) == 1
    assert isinstance(breaches[0], Breach)
    assert breaches[0].name == "TestBreach"
    assert breaches[0].domain == "example.com"
    assert breaches[0].pwn_count == 1000
    assert breaches[0].severity.value == "critical"


@patch("requests.Session.get")
def test_get_breached_account_no_breaches(mock_get, api):
    """Test the 404 / no-breach case."""
    mock_response = Mock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    breaches = api.get_breached_account("clean@example.com")

    assert len(breaches) == 0


@patch("requests.Session.get")
def test_api_error_handling(mock_get, api):
    """Test invalid API key error handling."""
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"
    mock_get.return_value = mock_response

    from src.breach_api import BreachAPIError

    with pytest.raises(BreachAPIError):
        api.get_breached_account("test@example.com")
