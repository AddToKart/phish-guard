from app.detector import analyze


def test_detects_obvious_phishing():
    result = analyze("http://192.168.1.2/secure-login", "<html><form>verify account urgently</form></html>")
    assert result["verdict"] == "phishing"
    assert result["score"] >= 0.7
    assert any("form" in signal["message"].lower() for signal in result["signals"])


def test_allows_legitimate_site():
    result = analyze("https://support.example.com/help", "<html><body>Documentation page</body></html>")
    assert result["verdict"] == "legitimate"
    assert result["score"] <= 0.45
