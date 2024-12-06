import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

class Config:
    # Flask Configurations
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')  # Default to avoid errors
    DEBUG = os.getenv('DEBUG', 'False').lower() in ['true', '1', 't']

    # PostgreSQL Configurations
    POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
    POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))
    POSTGRES_USER = os.getenv('POSTGRES_USER', 'postgres')
    POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', '')
    POSTGRES_DB = os.getenv('POSTGRES_DB', 'postgres')

    SQLALCHEMY_DATABASE_URI = (
        f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Redis Configurations
    REDIS_HOST = os.getenv('REDIS_HOST', 'master.msdb-redis-cluster-2.hvyzgq.aps1.cache.amazonaws.com')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', "thistokemforMSDBredis")
    REDIS_DB_MALWARE = int(os.getenv('REDIS_DB_MALWARE', 0))
    REDIS_DB_WHITE = int(os.getenv('REDIS_DB_WHITE', 1))

# # Redis Configurations
# REDIS_HOST=master.msdb-redis-cluster-2.hvyzgq.aps1.cache.amazonaws.com
# REDIS_PORT=6379
# REDIS_DB_WHITE=0
# REDIS_DB_MALWARE=1
# REDIS_PASSWORD=

    # Additional Settings
    API_RATE_LIMIT = os.getenv('API_RATE_LIMIT', '100/min')

class DevelopmentConfig(Config):
    ENV = 'development'
    DEBUG = True

class ProductionConfig(Config):
    ENV = 'production'
    DEBUG = False
