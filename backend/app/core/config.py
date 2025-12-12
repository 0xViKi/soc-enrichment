from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "soc-enrichment-backend"
    ENVIRONMENT: str = "local"

    # Database
    POSTGRES_HOST: str = "db"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "soc_enrich"
    POSTGRES_USER: str = "soc_user"
    POSTGRES_PASSWORD: str = "soc_password"

    # External APIs
    ABUSEIPDB_API_KEY: str | None = None
    IPINFO_TOKEN: str | None = None
    URLSCAN_API_KEY: str | None = None 
    VIRUSTOTAL_API_KEY: str | None = None 

    # Open Source EML Analyzer Endpoint
    EML_ANALYZER_URL: str = "https://eml-analyzer.herokuapp.com/api/analyze/file"

    # Internal API base (for self-calls from email → enrichment)
    INTERNAL_API_BASE_URL: str = "http://localhost:8000/api/v1"

    # Alerting / Webhooks
    SLACK_ALERT_WEBHOOK_URL: str | None = None
    GENERIC_ALERT_WEBHOOK_URL: str | None = None

    # Construct SQLAlchemy URL
    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:"
            f"{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:"
            f"{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
