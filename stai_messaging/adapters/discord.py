"""Discord slash-command adapter. Message-content intent is not requested."""

from __future__ import annotations

import asyncio
from typing import Any

from ..contracts import InboundMessage, OutboundReply
from ..formatting import split_text


class DiscordChannelAdapter:
    channel_name = "discord"

    def __init__(self, token: str, gateway: Any, identities: Any, account_id: str = "default") -> None:
        self.token = token
        self.gateway = gateway
        self.identities = identities
        self.account_id = account_id
        self.client: Any = None
        self._task: asyncio.Task | None = None
        self.status = "Disconnected"
        self.last_error = ""

    async def start(self) -> None:
        try:
            import discord
            from discord import app_commands
        except ImportError as exc:
            self.status = "Configuration Invalid"
            raise RuntimeError("Install discord.py to enable Discord") from exc

        intents = discord.Intents.none()
        self.client = discord.Client(intents=intents)
        self.tree = app_commands.CommandTree(self.client)

        @self.tree.command(name="pair", description="Request access to this SVS-Cyber agent")
        async def pair(interaction: discord.Interaction) -> None:
            if interaction.guild is not None:
                await interaction.response.send_message("Pairing is available in a direct message only.", ephemeral=True)
                return
            inbound = InboundMessage(
                channel=self.channel_name,
                account_id=self.account_id,
                sender_id=str(interaction.user.id),
                destination_id=str(interaction.channel_id),
                message_id=str(interaction.id),
                text="/pair",
            )
            request_id = self.identities.request_pairing(inbound)
            await interaction.response.send_message(
                f"Pairing request {request_id[:8]} is pending administrator review in SVS-Cyber settings.",
                ephemeral=True,
            )

        @self.tree.command(name="svs", description="Send a message to your paired SVS-Cyber agent")
        @app_commands.describe(message="Your question or investigation request")
        async def svs(interaction: discord.Interaction, message: str) -> None:
            if interaction.guild is not None:
                await interaction.response.send_message("Agent conversations are limited to direct messages.", ephemeral=True)
                return
            await interaction.response.defer(thinking=True)
            inbound = InboundMessage(
                channel=self.channel_name,
                account_id=self.account_id,
                sender_id=str(interaction.user.id),
                destination_id=str(interaction.channel_id),
                message_id=str(interaction.id),
                text=message[:4000],
            )
            reply = await self.gateway.handle(inbound, self)
            if reply is None:
                # Do not tell unpaired users whether an identity or agent exists.
                await interaction.followup.send("No response. Check pairing and account permissions in SVS-Cyber settings.", ephemeral=True)

        @self.client.event
        async def on_ready() -> None:
            try:
                await self.tree.sync()
                self.status = "Connected"
                self.last_error = ""
            except Exception as exc:
                self.status = "Error"
                self.last_error = type(exc).__name__

        @self.client.event
        async def on_disconnect() -> None:
            if self.status == "Connected":
                self.status = "Connecting"

        @self.client.event
        async def on_resumed() -> None:
            self.status = "Connected"
            self.last_error = ""

        self.status = "Connecting"
        self._task = asyncio.create_task(self.client.start(self.token), name="svs-discord")
        try:
            await asyncio.wait_for(self.client.wait_until_ready(), timeout=15)
        except Exception:
            if self._task.done():
                try:
                    self._task.result()
                except Exception as exc:
                    self.status = "Authentication Required" if isinstance(exc, discord.LoginFailure) else "Error"
                    self.last_error = type(exc).__name__
                    raise RuntimeError("Discord connection failed") from exc
            self.status = "Error"
            raise RuntimeError("Discord connection timed out")

    async def stop(self) -> None:
        if self.client is not None and not self.client.is_closed():
            await self.client.close()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._task.cancel()
        self.status = "Disconnected"

    async def send_message(self, reply: OutboundReply) -> None:
        if self.client is None or not self.client.is_ready():
            raise RuntimeError("Discord is not connected")
        destination = self.client.get_channel(int(reply.thread_id or "0"))
        if destination is None:
            destination = await self.client.fetch_channel(int(reply.thread_id or "0"))
        chunks = split_text(reply.text, 1900)
        for chunk in chunks:
            await destination.send(chunk, allowed_mentions=self._allowed_mentions())

    @staticmethod
    def _allowed_mentions() -> Any:
        import discord
        return discord.AllowedMentions.none()

    async def health_check(self) -> bool:
        return bool(self.client and self.client.is_ready() and not self.client.is_closed())
