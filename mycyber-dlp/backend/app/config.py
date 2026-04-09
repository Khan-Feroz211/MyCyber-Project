from functools import lru_cache
from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = ConfigDict(
        env_file=".env",
        protected_namespaces=("settings_",),
    )

    app_name: str = "MyCyber DLP"
    app_version: str = "2.0.0"
    debug: bool = False
    secret_key: str = "changeme"

    # NER / Transformer config
    ner_model_name: str = "dslim/bert-base-NER"
    ner_min_confidence: float = 0.85
    use_transformer: bool = True
    model_cache_dir: str = "/tmp/hf_models"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
