"""
Environment variable loader for development and production
Loads .env file in development, uses system environment in production
"""

import os
import logging

logger = logging.getLogger(__name__)

def load_env():
    """Load environment variables from .env file if it exists"""
    env_file = os.path.join(os.path.dirname(__file__), '.env')
    
    if os.path.exists(env_file):
        logger.info("Loading environment variables from .env file")
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Only set if not already in environment (allows override)
                    if key not in os.environ:
                        os.environ[key] = value
        logger.info("Environment variables loaded from .env file")
    else:
        logger.info("No .env file found, using system environment variables")

# Auto-load on import
load_env()