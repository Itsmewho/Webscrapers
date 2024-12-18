# Connect redis
import redis
import os
import logging
from dotenv import load_dotenv
from utils.helpers import reset, green, red

load_dotenv()

# Redis connection settings
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT"))
REDIS_DB = int(os.getenv("REDIS_DB"))

# Setup logger
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Setup Redis connection
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST"),
    port=os.getenv("REDIS_PORT"),
    db=0,
    decode_responses=True,
)


def get_redis_client():
    try:
        # Test connection
        redis_client.ping()
        logger.info(green + "Connected to Redis!" + reset)
        return redis_client
    except redis.ConnectionError as e:
        logger.error(red + f"Failed to connect to Redis: {e}" + reset)
        raise e
