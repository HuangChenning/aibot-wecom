def test_package_exposes_version():
    from wecom_aibot import __version__

    assert __version__ == "0.1.0"
