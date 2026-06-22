import discord
import asyncio
import logging
from discord.ext import commands
from core.config import Config
from core.external_scanners import ExternalScanners
from core.url_evaluator import URLEvaluator
from core.guild_settings import GuildSettings
from ai.agent import MariAgent
from bot.events import MessageHandler
from bot.commands import BasicCommands, AdminCommands

logger = logging.getLogger(__name__)


class MariBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True

        super().__init__(command_prefix="!", intents=intents)

        self.config = Config()
        self.scanners = ExternalScanners(self.config)
        self.evaluator = URLEvaluator(self.scanners)
        self.guild_settings = GuildSettings()
        self.agent = MariAgent(self.config)
        self.handler = MessageHandler(
            self.evaluator, self.config, self.guild_settings, self.agent
        )
        self.synced = False

    async def setup_hook(self):
        basic = BasicCommands(self)
        admin = AdminCommands(self)

        await self.add_cog(basic)
        await self.add_cog(admin)

        if self.config.GUILD_ID:
            guild = discord.Object(id=self.config.GUILD_ID)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
            logger.info("Synced app commands to guild %s", self.config.GUILD_ID)
        else:
            await self.tree.sync()
            logger.info("Synced global app commands")

        self.synced = True

        # Pre-load the URL model so the first scan doesn't block on a cold start.
        try:
            from ai.predict import load_model
            await asyncio.to_thread(load_model)
            logger.info("URL model pre-loaded.")
        except Exception as exc:
            logger.warning("Could not pre-load URL model: %s", exc)

    async def on_ready(self):
        print(f"Mari is here: {self.user}")
        logger.info(
            "Bot ready | user_id=%s | app_id=%s",
            getattr(self.user, "id", "unknown"),
            getattr(self, "application_id", "unknown"),
        )

    async def on_app_command_error(
        self, interaction: discord.Interaction, error: discord.app_commands.AppCommandError
    ):
        logger.warning("App command error: %s", error)
        if interaction.response.is_done():
            await interaction.followup.send("Command error. Please try again.", ephemeral=True)
        else:
            await interaction.response.send_message("Command error. Please try again.", ephemeral=True)

    async def on_message(self, message):
        if message.author.bot:
            return

        # MessageHandler xử lý toàn bộ: URL scan + OCR + ban + log
        await self.handler.handle(message)

        await self.process_commands(message)