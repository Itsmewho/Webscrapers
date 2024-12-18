# Connect redis
import redis
import os
import logging
from dotenv import load_dotenv
from utils.helpers import reset, green, red

load_dotenv()

# Redis connection settings
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))

# Setup logger
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def get_redis_client():
    try:
        client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
        # Test connection
        client.ping()
        logger.info(green + "Connected to Redis!" + reset)
        return client
    except redis.ConnectionError as e:
        logger.error(red + f"Failed to connect to Redis: {e}" + reset)
        raise e
