import os
import logging
from typing import Dict, Any
import yaml

logger = logging.getLogger("devguard.config")

DEFAULT_CONFIG = {
    "api": {
        "base_url": "https://dev.to/api",
        "api_key": "",
        "rate_limit": 10
    },
    "mode": "detect",
    "thresholds": {
        "suspicious": 0.4,
        "likely_bot": 0.7,
        "confirmed_bot": 0.9
    },
    "weights": {
        "content": 0.25,
        "profile": 0.20,
        "behavioral": 0.20,
        "fingerprint": 0.20,
        "ip_intel": 0.15
    },
    "service": {
        "enabled": True,
        "comment_scan_interval": 300,
        "follower_scan_interval": 900
    },
    "ip_intel": {
        "provider": "ip-api",
        "api_key": ""
    },
    "dashboard": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8420,
        "secret_key": "DEVGUARD_SECRET_KEY_CHANGE_ME"
    },
    "execute": {
        "enabled": False,
        "dry_run": True,
        "max_actions_per_hour": 10,
        "require_confirmation": True
    }
}

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Loads configuration from YAML file, falling back to environment variables or defaults."""
    config = DEFAULT_CONFIG.copy()
    
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                file_config = yaml.safe_load(f)
                if file_config and "devguard" in file_config:
                    deep_update(config, file_config["devguard"])
                    logger.info(f"Configuration loaded from {config_path}")
        except Exception as e:
            logger.error(f"Failed to parse config file {config_path}: {e}. Using defaults.")
    else:
        logger.info(f"Config file {config_path} not found. Using defaults.")

    # Override with Environment Variables if set
    # e.g., DEVGUARD_API_KEY overrides devguard.api.api_key
    env_mappings = {
        "DEVGUARD_API_KEY": ("api", "api_key"),
        "DEVGUARD_BASE_URL": ("api", "base_url"),
        "DEVGUARD_MODE": ("mode",),
        "DEVGUARD_EXECUTE_ENABLED": ("execute", "enabled"),
        "DEVGUARD_EXECUTE_DRY_RUN": ("execute", "dry_run"),
        "DEVGUARD_DB_URL": ("db_url",)  # Handled in database.py but useful here too
    }

    for env_var, path in env_mappings.items():
        val = os.getenv(env_var)
        if val is not None:
            # Convert boolean values
            if val.lower() in ("true", "1", "yes"):
                val = True
            elif val.lower() in ("false", "0", "no"):
                val = False
                
            # Update nested config dict
            target = config
            for key in path[:-1]:
                target = target.setdefault(key, {})
            target[path[-1]] = val
            logger.info(f"Config overridden from env var {env_var}")

    return config

def deep_update(d: dict, u: dict) -> dict:
    """Recursively updates a nested dictionary."""
    for k, v in u.items():
        if isinstance(v, dict):
            d[k] = deep_update(d.get(k, {}), v)
        else:
            d[k] = v
    return d
