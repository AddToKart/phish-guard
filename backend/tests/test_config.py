from app import config


def test_get_settings_reads_env(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
    config.get_settings.cache_clear()

    settings = config.get_settings()

    assert settings.gemini_api_key == "fake-key"

    # reset cache to avoid leaking into other tests
    config.get_settings.cache_clear()
    config.get_settings()
