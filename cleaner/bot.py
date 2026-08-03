"""
Telegram bot entry point.
"""

import asyncio
import logging
import os

from aiogram import Bot, Dispatcher
from dotenv import load_dotenv

from .handlers import router

# Load environment
load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")

if not TOKEN:
    raise ValueError("BOT_TOKEN not found in .env")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


async def main() -> None:
    """Main bot function."""
    bot = Bot(token=TOKEN)
    dp = Dispatcher()
    dp.include_router(router)

    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Bot failed: {e}")
        raise
