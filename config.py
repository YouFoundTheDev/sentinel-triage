"""Environment-backed configuration shared by the data pipeline and API."""

from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()


class Settings(BaseSettings):
    """Settings loaded from environment variables and an optional .env file."""

    google_cloud_project: str = ""
    google_cloud_location: str = "global"
    gemini_model: str = "gemini-3.8-flash"

    bq_dataset: str = "triage"
    bq_table: str = "indicators"
    bq_features_table: str = "url_features"
    bq_model: str = "url_classifier"
    bq_location: str = "US"

    data_dir: Path = Path("data/raw")
    clean_dir: Path = Path("data/clean")
    max_malicious_rows: int = Field(default=5000, ge=1)
    max_benign_rows: int = Field(default=5000, ge=1)
    dns_timeout_seconds: float = Field(default=5.0, gt=0)
    rdap_timeout_seconds: float = Field(default=5.0, gt=0)
    rdap_max_redirects: int = Field(default=2, ge=0, le=5)
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
