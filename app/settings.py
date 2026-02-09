from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    secret_key: str = "dev-secret"
    database_url: str = "sqlite:///./booking.db"
    cookie_secure: bool = False
    default_slot_minutes: int = 60

    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "admin123"


settings = Settings()
