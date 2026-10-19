"""Telegram polling adapter using python-telegram-bot's asyncio API."""

from __future__ import annotations

import asyncio
from typing import Any

from ..contracts import InboundMessage, OutboundReply
from ..formatting import split_text


class TelegramChannelAdapter:
    channel_name = "telegram"

    def __init__(self, token: str, gateway: Any, identities: Any, account_id: str = "default") -> None:
        self.token = token
        self.gateway = gateway
        self.identities = identities
        self.account_id = account_id
        self.application: Any = None
        self.status = "Disconnected"
        self.last_error = ""

    async def start(self) -> None:
        try:
            from telegram import Update
            from telegram.error import InvalidToken, RetryAfter
            from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
        except ImportError as exc:
            self.status = "Configuration Invalid"
            raise RuntimeError("Install python-telegram-bot to enable Telegram") from exc

        self.application = Application.builder().token(self.token).build()

        async def pair(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            user = update.effective_user
            chat = update.effective_chat
            if user is None or chat is None or chat.type != "private":
                if update.effective_message:
                    await update.effective_message.reply_text("Pairing is available in a private chat only.")
                return
            inbound = InboundMessage(
                channel=self.channel_name,
                account_id=self.account_id,
                sender_id=str(user.id),
                destination_id=str(chat.id),
                message_id=str(update.effective_message.message_id),
                text="/pair",
            )
            request_id = self.identities.request_pairing(inbound)
            await update.effective_message.reply_text(
                f"Pairing request {request_id[:8]} is pending administrator review in SVS-Cyber settings."
            )

        async def svs(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            user, chat, message = update.effective_user, update.effective_chat, update.effective_message
            if user is None or chat is None or message is None:
                return
            if chat.type != "private":
                await message.reply_text("Agent conversations are limited to private chats.")
                return
            text = " ".join(context.args).strip()
            if not text:
                await message.reply_text("Usage: /svs your question or investigation request")
                return
            inbound = InboundMessage(
                channel=self.channel_name,
                account_id=self.account_id,
                sender_id=str(user.id),
                destination_id=str(chat.id),
                message_id=str(message.message_id),
                text=text[:4000],
            )
            reply = await self.gateway.handle(inbound, self)
            if reply is None:
                await message.reply_text("No response. Check pairing and account permissions in SVS-Cyber settings.")

        async def text_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            self.status = "Connected"
            user, chat, message = update.effective_user, update.effective_chat, update.effective_message
            if user is None or chat is None or message is None or chat.type != "private":
                return
            inbound = InboundMessage(
                channel=self.channel_name,
                account_id=self.account_id,
                sender_id=str(user.id),
                destination_id=str(chat.id),
                message_id=str(message.message_id),
                reply_to_id=str(message.reply_to_message.message_id) if message.reply_to_message else None,
                text=(message.text or "")[:4000],
            )
            reply = await self.gateway.handle(inbound, self)
            if reply is None and self.identities.role_for(self.channel_name, self.account_id, str(user.id)) is None:
                # Silent default-deny for unknown senders; they can explicitly request pairing.
                return

        async def report_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
            error = context.error
            self.last_error = type(error).__name__ if error is not None else "TelegramError"
            if isinstance(error, RetryAfter):
                self.status = "Rate Limited"
            elif isinstance(error, InvalidToken):
                self.status = "Authentication Required"
            else:
                self.status = "Error"

        self.application.add_handler(CommandHandler("pair", pair))
        self.application.add_handler(CommandHandler("svs", svs))
        self.application.add_handler(CommandHandler("status", self._status))
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_message))
        self.application.add_error_handler(report_error)
        self.status = "Connecting"
        try:
            await self.application.initialize()
            await self.application.start()
            if self.application.updater is None:
                raise RuntimeError("Telegram polling is unavailable")
            await self.application.updater.start_polling(drop_pending_updates=False)
            me = await self.application.bot.get_me()
            self.status = "Connected"
            self.last_error = ""
            self.bot_username = me.username
        except Exception as exc:
            self.status = "Authentication Required" if isinstance(exc, InvalidToken) else "Error"
            self.last_error = type(exc).__name__
            await self.stop()
            raise RuntimeError("Telegram connection failed") from exc

    async def _status(self, update: Any, context: Any) -> None:
        user, chat, message = update.effective_user, update.effective_chat, update.effective_message
        if user is None or chat is None or message is None or chat.type != "private":
            return
        inbound = InboundMessage(
            channel=self.channel_name, account_id=self.account_id, sender_id=str(user.id),
            destination_id=str(chat.id), message_id=str(message.message_id), text="/status",
        )
        reply = await self.gateway.handle(inbound, self)
        if reply is None:
            await message.reply_text("No response. Check pairing and account permissions in SVS-Cyber settings.")

    async def stop(self) -> None:
        if self.application is None:
            self.status = "Disconnected"
            return
        updater = self.application.updater
        if updater is not None and updater.running:
            await updater.stop()
        if self.application.running:
            await self.application.stop()
        await self.application.shutdown()
        self.status = "Disconnected"

    async def send_message(self, reply: OutboundReply) -> None:
        if self.application is None or not self.application.running:
            raise RuntimeError("Telegram is not connected")
        chat_id = reply.thread_id
        if not chat_id:
            raise ValueError("Telegram destination is missing")
        for chunk in split_text(reply.text, 4000):
            await self.application.bot.send_message(chat_id=chat_id, text=chunk, parse_mode=None)

    async def health_check(self) -> bool:
        return bool(self.application and self.application.running and self.status == "Connected")
