from connection.connect_redis import get_redis_client
from utils.helpers import green, blue, red, reset
import logging
import json

redis_client = get_redis_client()

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def set_cache(key, value, expiry=3600):

    try:
        redis_client.setex(key, expiry, json.dumps(value))
        logger.info(green + f"Cache set for key: {key}" + reset)
    except Exception as e:
        logger.error(red + f"Failed to set cache for key: {key}. Error: {e}" + reset)


def get_cache(key):

    try:
        value = redis_client.get(key)
        if value:
            logger.info(blue + f"Cache hit for key: {key}" + reset)
            return json.loads(value)
        logger.info(blue + f"Cache miss for key: {key}" + reset)
        return None
    except Exception as e:
        logger.error(red + f"Failed to get cache for key: {key}. Error: {e}" + reset)
        return None


def delete_cache(key):

    try:
        redis_client.delete(key)
        logger.info(green + f"Cache cleared for key: {key}" + reset)
    except Exception as e:
        logger.error(red + f"Failed to clear cache for key: {key}. Error: {e}" + reset)
