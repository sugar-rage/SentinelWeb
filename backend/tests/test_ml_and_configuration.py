import pytest

from app.core.config import Settings
from app.ml.predictor import MLPredictor
from app.services.risk_service import calculate_risk_score, get_risk_level, should_block


def test_ml_predictor_loads_and_detects_known_sqli():
    predictor = MLPredictor()
    assert predictor.load_models() is True
    result = predictor.predict("1' OR '1'='1' --")
    assert result.is_available is True
    assert result.is_attack is True
    assert result.predicted_class == "SQL Injection"
    assert result.confidence >= 0.85


def test_ml_predictor_falls_back_safely_when_artifacts_are_missing():
    predictor = MLPredictor(models_dir="C:/sentinelweb-nonexistent-test-models")
    result = predictor.predict("1' OR '1'='1' --")
    assert result.is_available is False
    assert result.is_attack is False
    assert "Missing model artifacts" in (result.error or "")


def test_risk_scoring_policy_boundaries():
    score = calculate_risk_score(0.85, "SQL Injection")
    assert score == 81
    assert get_risk_level(score) == "Critical"
    assert should_block(score) is True
    assert should_block(79) is False


def test_production_configuration_rejects_weak_secret(monkeypatch):
    monkeypatch.setenv("SENTINELWEB_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql://db.example/sentinelweb")
    monkeypatch.setenv("CORS_ORIGINS", "https://sentinel.example")
    monkeypatch.setenv("JWT_SECRET", "short")
    with pytest.raises(RuntimeError, match="strong JWT_SECRET"):
        Settings().validate_runtime_configuration()


def test_production_configuration_accepts_environment_values(monkeypatch):
    monkeypatch.setenv("SENTINELWEB_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql://db.example/sentinelweb")
    monkeypatch.setenv("CORS_ORIGINS", "https://sentinel.example,https://admin.example")
    monkeypatch.setenv("JWT_SECRET", "a" * 32)
    settings = Settings()
    settings.validate_runtime_configuration()
    assert settings.CORS_ORIGINS == ["https://sentinel.example", "https://admin.example"]


def test_production_configuration_requires_database_url(monkeypatch):
    monkeypatch.setenv("SENTINELWEB_ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("CORS_ORIGINS", "https://sentinel.example")
    monkeypatch.setenv("JWT_SECRET", "a" * 32)
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        Settings().validate_runtime_configuration()
