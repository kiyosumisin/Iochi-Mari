"""Mari's command cogs, split by area of responsibility.

`ALL_COGS` is the single list the bot loads in `setup_hook`; add a new cog
class here and it will be registered automatically.
"""

from .basic import BasicCommands
from .moderation import ModerationCommands
from .config_cmds import ConfigCommands
from .reports import ReportCommands
from .owner import OwnerCommands
from .datamine import DatamineCommands

ALL_COGS = [
    BasicCommands,
    ModerationCommands,
    ConfigCommands,
    ReportCommands,
    OwnerCommands,
    DatamineCommands,
]
