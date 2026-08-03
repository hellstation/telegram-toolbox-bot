import logging
import os
import tempfile
from typing import Dict

from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import BufferedInputFile, FSInputFile, KeyboardButton, ReplyKeyboardMarkup, Message

from .cleaner import calculate_score, clean_cookies, get_sites_by_category
from .osint import TOOL_PROMPTS, TOOL_TITLES, run_tool, is_ip_address
from .security.service import (
    DomainReport,
    analyze_domain_report,
    check_domain_rate_limit,
)

logger = logging.getLogger(__name__)

router = Router()

class CookieStates(StatesGroup):
    waiting_for_file = State()

class MenuStates(StatesGroup):
    main_menu = State()
    id_menu = State()
    get_id_waiting = State()
    osint_menu = State()
    osint_waiting = State()


def main_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🍪 Cookie Cleaner")],
            [KeyboardButton(text="🆔 ID"), KeyboardButton(text="🕵️ Simple OSINT tool")],
        ],
        resize_keyboard=True
    )


def osint_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="👤 Username"), KeyboardButton(text="🌐 IP Tracker")],
            [KeyboardButton(text="📞 Phone"), KeyboardButton(text="🚗 Vehicle")],
            [KeyboardButton(text="🌍 WHOIS / Domain"), KeyboardButton(text="📧 SMTP")],
            [KeyboardButton(text="🔗 Connections")],
            [KeyboardButton(text="🔙 Back")],
        ],
        resize_keyboard=True
    )


def osint_result_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔄 OSINT Again")],
            [KeyboardButton(text="🔙 Back"), KeyboardButton(text="🏠 Main Menu")],
        ],
        resize_keyboard=True
    )


OSINT_BUTTONS = {
    "👤 Username": "username",
    "🌐 IP Tracker": "ip",
    "📞 Phone": "phone",
    "🚗 Vehicle": "vehicle",
    "🌍 WHOIS / Domain": "domain",
    "📧 SMTP": "smtp",
    "🔗 Connections": "connections",
}


@router.message(F.text == "/start")
async def start(message: Message, state: FSMContext) -> None:
    main_msg = await message.answer("Welcome! Choose an action:", reply_markup=main_keyboard())
    await state.update_data(main_message_id=main_msg.message_id)
    await state.set_state(MenuStates.main_menu)

@router.message(F.text == "🍪 Cookie Cleaner")
async def cookie_cleaner_message(message: Message, state: FSMContext) -> None:
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="❌ Cancel")]
        ],
        resize_keyboard=True
    )
    status_msg = await message.answer("📤 Upload your cookies file (Edge format):", reply_markup=keyboard)
    await state.update_data(message_id=status_msg.message_id)
    await state.set_state(CookieStates.waiting_for_file)


def _build_cookie_stats_report(stats: Dict) -> tuple[str, int, str]:
    """Build stats report text. Returns (report_text, score, level)."""
    site_counter = {site: count for site, count in stats["sites"].items()}
    service_counter = {
        site: {svc: 1 for svc in svcs} for site, svcs in stats["services"].items()
    }
    auth_detected = {
        site: set(cookies) for site, cookies in stats["auth_detected"].items()
    }
    score, level, _ = calculate_score(site_counter, service_counter, auth_detected)
    categories = get_sites_by_category(site_counter)

    lines = [f"🧠 SCORE: {score} ({level})", ""]

    for site, count in stats["sites"].items():
        services = ", ".join([s for s in stats["services"].get(site, []) if s])
        if services:
            lines.append(f"{site}({count}) - {services}")
        else:
            lines.append(f"{site}({count})")

    if stats["auth_detected"]:
        lines.append("")
        lines.append("🔐 AUTH DETECTED:")
        for site, cookies in stats["auth_detected"].items():
            lines.append(f"{site}: {', '.join(cookies)}")

    lines.extend(
        [
            "",
            "=== STATISTICS ===",
            f"Total unique cookies: {stats['total_unique_cookies']}",
            f"Unique main domains: {stats['unique_sites']}",
            f"Most common domain: {stats['most_common_site']}",
            f"Oldest cookies age: {stats.get('oldest_cookie_age', 'Unknown')}",
            f"Tracking cookies detected: {stats.get('tracking_intensity', 0)}",
            f"🏆 Privacy Score: {stats.get('privacy_score', 0.0)}/10.0",
        ]
    )

    if categories:
        lines.append("")
        lines.append("=== BY CATEGORIES ===")
        for category, sites in categories.items():
            if sites:
                lines.append(f"{category.capitalize()}: {', '.join(sites)}")

    return "\n".join(lines) + "\n", score, level


@router.message(CookieStates.waiting_for_file, F.document)
async def file_handler(message: Message, state: FSMContext) -> None:
    document = message.document
    if not document:
        await message.answer("Please upload a file.")
        return

    if message.media_group_id is not None:
        await message.answer("Please upload only one txt file at a time.")
        return

    data = await state.get_data()
    status_message_id = data.get("message_id")

    if not status_message_id:
        await message.answer("Session error. Please start over.")
        await state.clear()
        return

    temp_input = None
    temp_output = None
    stats_file = None

    try:
        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text="⏳ Processing your cookie file...",
            )
        except Exception:
            status_msg = await message.answer("⏳ Processing your cookie file...")
            await state.update_data(message_id=status_msg.message_id)
            status_message_id = status_msg.message_id

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as temp_file:
            temp_input = temp_file.name
            await message.bot.download(document, temp_input)

        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text="🧹 Cleaning cookies...",
            )
        except Exception:
            status_msg = await message.answer("🧹 Cleaning cookies...")
            await state.update_data(message_id=status_msg.message_id)
            status_message_id = status_msg.message_id

        # clean_cookies writes real cleaned cookie lines to temp_output — do not overwrite
        temp_output = temp_input + "_cleaned.txt"
        stats: Dict = clean_cookies(temp_input, temp_output)

        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text="📊 Generating statistics...",
            )
        except Exception:
            status_msg = await message.answer("📊 Generating statistics...")
            await state.update_data(message_id=status_msg.message_id)
            status_message_id = status_msg.message_id

        report_content, score, level = _build_cookie_stats_report(stats)
        stats_file = temp_input + "_stats.txt"
        with open(stats_file, "w", encoding="utf-8") as f:
            f.write(report_content)

        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text="✅ Processing complete! Sending results...",
            )
        except Exception:
            await message.answer("✅ Processing complete! Sending results...")

        original_name = os.path.splitext(document.file_name or "cookies")[0]
        cleaned_filename = f"cleaned_{original_name}.txt"
        stats_filename = f"stats_{original_name}.txt"

        keyboard = ReplyKeyboardMarkup(
            keyboard=[
                [KeyboardButton(text="🔄 Upload Another"), KeyboardButton(text="❌ Cancel")]
            ],
            resize_keyboard=True,
        )

        # 1) Actual cleaned cookies (Netscape/Edge lines)
        await message.answer_document(
            FSInputFile(temp_output, filename=cleaned_filename),
            caption=f"🍪 Cleaned cookies. Total kept: {stats['total_cleaned']}",
        )
        # 2) Separate stats/report file — never overwrite cleaned cookies
        await message.answer_document(
            FSInputFile(stats_file, filename=stats_filename),
            caption=(
                f"📊 Report. Score: {score} ({level})\n"
                f"Privacy: {stats.get('privacy_score', 0.0)}/10.0\n\n"
                f"Choose an action:"
            ),
            reply_markup=keyboard,
        )

        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text="✅ Processing complete!",
            )
        except Exception:
            pass

        logger.info(
            "Processed cookies for user %s",
            message.from_user.id if message.from_user else "?",
        )

    except Exception as e:
        logger.error("Error processing file: %s", e)
        keyboard = ReplyKeyboardMarkup(
            keyboard=[
                [KeyboardButton(text="🔄 Upload Another"), KeyboardButton(text="❌ Cancel")]
            ],
            resize_keyboard=True,
        )
        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text=f"❌ Error: {str(e)}\n\nUpload another file or cancel:",
                reply_markup=keyboard,
            )
        except Exception:
            await message.answer(
                f"Error processing file: {str(e)}\n\nChoose an action:",
                reply_markup=keyboard,
            )
            await state.clear()
    finally:
        for file_path in [temp_input, temp_output, stats_file]:
            if file_path and os.path.exists(file_path):
                os.unlink(file_path)



@router.message(F.text == "🆔 ID")
async def id_menu_message(message: Message, state: FSMContext) -> None:
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="👤 Get my ID"), KeyboardButton(text="🔍 Get ID")],
            [KeyboardButton(text="🔙 Back")]
        ],
        resize_keyboard=True
    )
    await message.answer("🆔 ID Tools:", reply_markup=keyboard)
    await state.set_state(MenuStates.id_menu)
    await state.update_data(last_menu_type='id')


@router.message(F.text == "🕵️ Simple OSINT tool")
async def osint_menu_message(message: Message, state: FSMContext) -> None:
    await message.answer("🕵️ OSINT Tools:", reply_markup=osint_keyboard())
    await state.set_state(MenuStates.osint_menu)
    await state.update_data(last_menu_type='osint')


@router.message(F.text.in_(set(OSINT_BUTTONS.keys())))
async def osint_tool_message(message: Message, state: FSMContext) -> None:
    tool = OSINT_BUTTONS[message.text]
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔙 Back"), KeyboardButton(text="🏠 Main Menu")]
        ],
        resize_keyboard=True
    )
    await state.update_data(selected_osint_tool=tool, last_menu_type='osint')
    await message.answer(TOOL_PROMPTS[tool], reply_markup=keyboard)
    await state.set_state(MenuStates.osint_waiting)


@router.message(F.text == "🔄 OSINT Again")
async def osint_again_message(message: Message, state: FSMContext) -> None:
    data = await state.get_data()
    tool = data.get("selected_osint_tool")
    if tool:
        keyboard = ReplyKeyboardMarkup(
            keyboard=[
                [KeyboardButton(text="🔙 Back"), KeyboardButton(text="🏠 Main Menu")]
            ],
            resize_keyboard=True
        )
        await message.answer(TOOL_PROMPTS[tool], reply_markup=keyboard)
        await state.set_state(MenuStates.osint_waiting)
        return
    await message.answer("🕵️ OSINT Tools:", reply_markup=osint_keyboard())
    await state.set_state(MenuStates.osint_menu)
    await state.update_data(last_menu_type='osint')


@router.message(MenuStates.osint_waiting, F.text, ~F.text.in_({"🔙 Back", "🏠 Main Menu"}))
async def osint_query_message(message: Message, state: FSMContext) -> None:
    data = await state.get_data()
    tool = data.get("selected_osint_tool")
    if not tool:
        await message.answer("❌ OSINT session expired. Choose a tool again.", reply_markup=osint_keyboard())
        await state.set_state(MenuStates.osint_menu)
        return

    # Full domain security analysis → HTML report (kkkk-style)
    if tool == "domain" and not is_ip_address(message.text.strip()):
        user_id = message.from_user.id if message.from_user else 0
        remaining = check_domain_rate_limit(user_id)
        if remaining is not None:
            await message.answer(
                f"⏳ Too many domain scans. Wait {remaining}s before the next analysis."
            )
            return

        status_msg = await message.answer(
            f"⏳ Analyzing domain security for {message.text.strip()}…\n"
            f"This may take 10–60 seconds (WHOIS, DNS, tech, CVE, SSL…)."
        )
        try:
            report = await analyze_domain_report(message.text)
        except Exception as e:
            logger.exception("Domain security analysis failed")
            try:
                await status_msg.edit_text(f"❌ Domain analysis failed: {str(e)[:300]}")
            except Exception:
                await message.answer(f"❌ Domain analysis failed: {str(e)[:300]}")
            await message.answer("Choose an action:", reply_markup=osint_result_keyboard())
            await state.set_state(MenuStates.osint_menu)
            await state.update_data(last_menu_type="osint")
            return

        if isinstance(report, str):
            try:
                await status_msg.edit_text(report)
            except Exception:
                await message.answer(report)
            await message.answer("Choose an action:", reply_markup=osint_result_keyboard())
            await state.set_state(MenuStates.osint_menu)
            await state.update_data(last_menu_type="osint")
            return

        assert isinstance(report, DomainReport)
        safe_filename = f"report_{report.domain.replace('.', '_')}.html"
        document = BufferedInputFile(report.html.encode("utf-8"), filename=safe_filename)
        try:
            await status_msg.delete()
        except Exception:
            pass
        await message.answer_document(document=document, caption=report.caption)
        await message.answer("Choose an action:", reply_markup=osint_result_keyboard())
        await state.set_state(MenuStates.osint_menu)
        await state.update_data(last_menu_type="osint")
        return

    status_msg = await message.answer(f"⏳ Running {TOOL_TITLES.get(tool, 'OSINT')}...")
    result = await run_tool(tool, message.text)
    title = TOOL_TITLES.get(tool, "OSINT")

    if tool == "username" and len(result) > 3900:
        await status_msg.edit_text("✅ Username scan complete. Sending result in parts...")
        for part in split_message(result):
            await message.answer(part)
    elif len(result) <= 3900:
        await status_msg.edit_text(result)
    else:
        filename = f"osint_{tool}_result.txt"
        await status_msg.edit_text("✅ Result is too long, sending as a file...")
        await message.answer_document(
            BufferedInputFile(result.encode("utf-8"), filename=filename),
            caption=f"{title} result",
        )

    await message.answer("Choose an action:", reply_markup=osint_result_keyboard())
    await state.set_state(MenuStates.osint_menu)
    await state.update_data(last_menu_type='osint')


def split_message(text: str, limit: int = 3900) -> list[str]:
    parts = []
    current = ""
    for line in text.splitlines():
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) <= limit:
            current = candidate
            continue
        if current:
            parts.append(current)
        current = line
    if current:
        parts.append(current)
    return parts

@router.message(F.text == "👤 Get my ID", MenuStates.id_menu)
async def get_my_id_message(message: Message, state: FSMContext) -> None:
    user_id = message.from_user.id
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔙 Back"), KeyboardButton(text="🏠 Main Menu")]
        ],
        resize_keyboard=True
    )
    await message.answer(f"👤 Your ID: `{user_id}`", parse_mode="Markdown", reply_markup=keyboard)

@router.message(F.text == "🔍 Get ID")
async def get_id_message(message: Message, state: FSMContext) -> None:
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔙 Back"), KeyboardButton(text="🏠 Main Menu")]
        ],
        resize_keyboard=True
    )
    await message.answer("🔍 Forward a message to get the sender's ID:", reply_markup=keyboard)
    await state.set_state(MenuStates.get_id_waiting)

@router.message(F.text == "🔍 Get Another ID")
async def get_another_id_message(message: Message, state: FSMContext) -> None:
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔙 Back"), KeyboardButton(text="🏠 Main Menu")]
        ],
        resize_keyboard=True
    )
    await message.answer("🔍 Forward a message to get the sender's ID:", reply_markup=keyboard)
    await state.set_state(MenuStates.get_id_waiting)

@router.message(F.text == "🏠 Main Menu")
async def back_to_main_message(message: Message, state: FSMContext) -> None:
    await message.answer("Welcome! Choose an action:", reply_markup=main_keyboard())
    await state.set_state(MenuStates.main_menu)

@router.message(F.text == "🔙 Back")
async def back_button_handler(message: Message, state: FSMContext) -> None:
    current_state = await state.get_state()
    data = await state.get_data()
    last_menu_type = data.get('last_menu_type', 'main')

    if last_menu_type == 'osint':
        if current_state and str(current_state).endswith('osint_waiting'):
            await message.answer("🕵️ OSINT Tools:", reply_markup=osint_keyboard())
            await state.set_state(MenuStates.osint_menu)
            return
        await message.answer("Welcome! Choose an action:", reply_markup=main_keyboard())
        await state.set_state(MenuStates.main_menu)
        await state.update_data(last_menu_type='main')
    elif (current_state and str(current_state).endswith('id_menu')) or last_menu_type == 'id':
        await message.answer("Welcome! Choose an action:", reply_markup=main_keyboard())
        await state.set_state(MenuStates.main_menu)
        await state.update_data(last_menu_type='main')
    else:
        keyboard = ReplyKeyboardMarkup(
            keyboard=[
                [KeyboardButton(text="👤 Get my ID"), KeyboardButton(text="🔍 Get ID")],
                [KeyboardButton(text="🔙 Back")]
            ],
            resize_keyboard=True
        )
        await message.answer("🆔 ID Tools:", reply_markup=keyboard)
        await state.set_state(MenuStates.id_menu)
        await state.update_data(last_menu_type='id')

@router.message(F.forward_origin, MenuStates.get_id_waiting)
async def handle_forwarded_message(message: Message, state: FSMContext) -> None:
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="🔍 Get Another ID")],
            [KeyboardButton(text="🏠 Main Menu")]
        ],
        resize_keyboard=True
    )

    if message.forward_origin:
        if hasattr(message.forward_origin, 'sender_user') and message.forward_origin.sender_user:
            original_user = message.forward_origin.sender_user
            user_id = original_user.id
            username = original_user.username or "No username"

            await message.reply(
                f"🔍 **Sender ID:** `{user_id}`\n**Username:** @{username}",
                parse_mode="Markdown",
                reply_markup=keyboard
            )

        elif hasattr(message.forward_origin, 'chat') and message.forward_origin.chat:
            chat = message.forward_origin.chat
            chat_id = chat.id
            chat_title = getattr(chat, 'title', 'Unknown chat')

            await message.reply(
                f"🔍 **Chat ID:** `{chat_id}`\n**Chat:** {chat_title}",
                parse_mode="Markdown",
                reply_markup=keyboard
            )

        else:
            await message.reply("❌ Unable to extract ID from this message.", reply_markup=keyboard)

    else:
        if message.forward_origin:
            if hasattr(message.forward_origin, 'sender_user') and message.forward_origin.sender_user:
                original_user = message.forward_origin.sender_user
                user_id = original_user.id
                username = original_user.username or "No username"
                await message.answer(f"Original sender ID: `{user_id}`\nUsername: @{username}", parse_mode="Markdown")
            elif hasattr(message.forward_origin, 'chat') and message.forward_origin.chat:
                chat = message.forward_origin.chat
                chat_id = chat.id
                chat_title = getattr(chat, 'title', 'Unknown chat')
                await message.answer(f"Original chat ID: `{chat_id}`\nChat: {chat_title}", parse_mode="Markdown")
            else:
                await message.answer("Unable to extract ID from this forwarded message.")

@router.message(F.text == "🔄 Upload Another")
async def upload_another_message(message: Message, state: FSMContext) -> None:
    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="❌ Cancel")]
        ],
        resize_keyboard=True
    )
    status_msg = await message.answer("📤 Upload your cookies file (Edge format):", reply_markup=keyboard)
    await state.update_data(message_id=status_msg.message_id)
    await state.set_state(CookieStates.waiting_for_file)

@router.message(F.text == "❌ Cancel")
async def cancel_message(message: Message, state: FSMContext) -> None:
    await message.answer("Action cancelled.", reply_markup=main_keyboard())
    await state.clear()
    await state.set_state(MenuStates.main_menu)
