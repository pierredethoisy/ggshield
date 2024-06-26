from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests.exceptions
from _pytest.monkeypatch import MonkeyPatch
from pyfakefs.fake_filesystem import FakeFilesystem

import ggshield.core
from ggshield.core.check_updates import CACHE_FILE, check_for_updates


@patch("requests.get")
@pytest.mark.parametrize(
    "current_version,remote_version,expected_latest_version",
    (
        ("1.2.3", "1.2.4", "1.2.4"),
        ("1.2.3", "1.3.3", "1.3.3"),
        ("1.2.3", "2.2.3", "2.2.3"),
        ("1.2.3", "1.2.3", None),
        ("1.2.3", "1.2.2", None),
        ("1.2.3", "1.1.3", None),
        ("1.2.3", "0.2.3", None),
    ),
)
def test_check_for_updates(
    request_get_mock: Mock,
    current_version: str,
    remote_version: str,
    expected_latest_version: bool,
    fs: FakeFilesystem,
    monkeypatch: MonkeyPatch,
):
    """
    GIVEN the latest released version
    WHEN calling check_for_updates
    THEN the latest version is returned if it's newer
    """
    monkeypatch.setattr(ggshield.core.check_updates, "__version__", current_version)
    request_get_mock.return_value.status_code = 200
    request_get_mock.return_value.json.return_value = {"tag_name": f"v{remote_version}"}

    latest_version = check_for_updates()

    assert latest_version == expected_latest_version
    assert fs.exists(CACHE_FILE)


@patch("requests.get")
def test_check_for_updates_twice_only_notifies_once(
    request_get_mock: Mock, fs: FakeFilesystem, monkeypatch: MonkeyPatch
):
    """
    GIVEN a first check_for_updates() call
    WHEN calling check_for_updates() a second time
    THEN no network calls are made and no update is reported
    """
    monkeypatch.setattr(ggshield.core.check_updates, "__version__", "1.0")

    request_get_mock.return_value.status_code = 200
    request_get_mock.return_value.json.return_value = {"tag_name": "v1.1"}
    latest_version = check_for_updates()
    assert latest_version == "1.1"

    request_get_mock.reset_mock()
    latest_version = check_for_updates()

    request_get_mock.assert_not_called()
    assert latest_version is None


@patch("requests.get")
def test_check_for_updates_request_exceptions_are_caught(
    request_get_mock: Mock, fs: FakeFilesystem
):
    """
    GIVEN an environment with no network access to api.github.com
    WHEN check_for_updates() is called
    THEN it does not fail
    AND the check time is recorded to avoid rechecking every time
    """
    request_get_mock.side_effect = requests.exceptions.ConnectTimeout()
    latest_version = check_for_updates()
    assert latest_version is None

    assert fs.exists(CACHE_FILE)


@patch("requests.get")
def test_check_for_updates_does_nothing_if_cache_cant_be_saved(
    request_get_mock: Mock, fs: FakeFilesystem
):
    """
    GIVEN an environment where it is not possible to save the check time
    WHEN check_for_updates() is called
    THEN it does not fail
    AND no network access happens
    """
    # Create the cache file as a directory to simulate the case where the cache file is
    # not writable
    Path(CACHE_FILE).mkdir(parents=True, exist_ok=False)

    latest_version = check_for_updates()
    assert latest_version is None
    request_get_mock.assert_not_called()
