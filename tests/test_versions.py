from patchorder.versions import compare_versions, version_is_comparable, windows_build_comparable


def test_numeric_order_and_padding():
    assert compare_versions("1.25.2", "1.25.3") < 0
    assert compare_versions("1.25", "1.25.0") == 0
    assert compare_versions("3.0.12", "3.0.13") < 0
    assert compare_versions("3.0.13", "3.0.13") == 0


def test_openssl_letter_and_openssh_portable_suffix():
    assert compare_versions("1.1.1w", "1.1.1x") < 0
    assert compare_versions("1.1.1", "1.1.1w") < 0
    assert compare_versions("1.0.2zj", "1.0.2zk") < 0
    assert compare_versions("9.8", "9.8p1") < 0
    assert compare_versions("9.6", "9.8") < 0
    assert compare_versions("8.5p1", "8.6") < 0


def test_windows_builds():
    assert compare_versions("10.0.20348.2400", "10.0.20348.2655") < 0
    assert compare_versions("10.0.22631.3593", "10.0.22631.4037") < 0
    assert compare_versions("10.0.22631.4037", "10.0.22631.4036") > 0
    assert windows_build_comparable("10.0.22631.4037")
    ok, reason = version_is_comparable("microsoft", "windows_server_2022", "2022")
    assert not ok
    assert "10.0.22631.4037" in reason
    ok, _ = version_is_comparable("microsoft", "windows_11_23h2", "10.0.22631.3593")
    assert ok
    ok, _ = version_is_comparable("openssl", "openssl", "3.0.12")
    assert ok
