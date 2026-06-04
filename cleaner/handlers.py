import logging
import os
import tempfile
import time
from typing import Dict

from aiogram import Router, F
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import BufferedInputFile, FSInputFile, KeyboardButton, ReplyKeyboardMarkup, Message

from .metrics import messages_processed, commands_processed, errors_total, processing_time, files_processed
from .cleaner import clean_cookies, get_sites_by_category
from .osint import TOOL_PROMPTS, TOOL_TITLES, run_tool

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
    messages_processed.inc()
    commands_processed.labels(command="/start").inc()
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


@router.message(F.document)
async def file_handler(message: Message, state: FSMContext) -> None:
    messages_processed.inc()
    document = message.document
    if not document:
        await message.answer("Please upload a file.")
        return

    if message.media_group_id is not None:
        await message.answer("Please upload only one txt file at a time.")
        return

    data = await state.get_data()
    status_message_id = data.get('message_id')

    if not status_message_id:
        await message.answer("Session error. Please start over.")
        await state.clear()
        return

    temp_input = None
    temp_output = None
    stats_file = None

    start_time = time.time()
    try:
        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text="⏳ Processing your cookie file..."
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
                text="🧹 Cleaning cookies..."
            )
        except Exception:
            status_msg = await message.answer("🧹 Cleaning cookies...")
            await state.update_data(message_id=status_msg.message_id)
            status_message_id = status_msg.message_id

        temp_output = temp_input + "_cleaned.txt"
        stats: Dict = clean_cookies(temp_input, temp_output)

        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text="📊 Generating statistics..."
            )
        except Exception:
            status_msg = await message.answer("📊 Generating statistics...")
            await state.update_data(message_id=status_msg.message_id)
            status_message_id = status_msg.message_id

        stats_file = temp_input + "_stats.txt"
        with open(stats_file, "w", encoding="utf-8") as f:
            from .cleaner import calculate_score
            site_counter = {site: count for site, count in stats["sites"].items()}
            service_counter = {site: {svc: 1 for svc in svcs} for site, svcs in stats["services"].items()}
            auth_detected = {site: set(cookies) for site, cookies in stats["auth_detected"].items()}
            score, level, _ = calculate_score(site_counter, service_counter, auth_detected)
            categories = get_sites_by_category(site_counter)
            f.write(f"🧠 SCORE: {score} ({level})\n\n")

            for site, count in stats["sites"].items():
                site_name = site
                services = ", ".join([s for s in stats["services"].get(site, []) if s])
                if services:
                    f.write(f"{site_name}({count}) - {services}\n")
                else:
                    f.write(f"{site_name}({count})\n")

            if stats["auth_detected"]:
                f.write("\n🔐 AUTH DETECTED:\n")
                for site, cookies in stats["auth_detected"].items():
                    site_name = site
                    f.write(f"{site_name}: {', '.join(cookies)}\n")

            f.write(f"\n=== STATISTICS ===\n")
            f.write(f"Total unique cookies: {stats['total_unique_cookies']}\n")
            f.write(f"Unique main domains: {stats['unique_sites']}\n")
            f.write(f"Most common domain: {stats['most_common_site']}\n")
            f.write(f"Oldest cookies age: {stats.get('oldest_cookie_age', 'Unknown')}\n")
            f.write(f"Tracking cookies detected: {stats.get('tracking_intensity', 0)}\n")
            f.write(f"🏆 Privacy Score: {stats.get('privacy_score', 0.0)}/10.0\n")

            if categories:
                f.write("\n=== BY CATEGORIES ===\n")
                for category, sites in categories.items():
                    if sites:
                        f.write(f"{category.capitalize()}: {', '.join(sites)}\n")

        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text="✅ Processing complete! Sending results..."
            )
        except Exception:
            await message.answer("✅ Processing complete! Sending results...")

        # Get original filename without extension
        original_name = os.path.splitext(document.file_name)[0]
        cleaned_filename = f"cleaned_{original_name}.txt"

        keyboard = ReplyKeyboardMarkup(
            keyboard=[
                [KeyboardButton(text="🔄 Upload Another"), KeyboardButton(text="❌ Cancel")]
            ],
            resize_keyboard=True
        )

        # Create the full formatted report content
        report_content = f"""🧠 SCORE: {score} ({level})

"""

        # Add site information
        for site, count in stats["sites"].items():
            site_name = site
            services = ", ".join([s for s in stats["services"].get(site, []) if s])
            if services:
                report_content += f"{site_name}({count}) - {services}\n"
            else:
                report_content += f"{site_name}({count})\n"

        # Add auth detected section
        if stats["auth_detected"]:
            report_content += "\n🔐 AUTH DETECTED:\n"
            for site, cookies in stats["auth_detected"].items():
                site_name = site
                report_content += f"{site_name}: {', '.join(cookies)}\n"

        # Add statistics section
        report_content += f"""
=== STATISTICS ===
Total unique cookies: {stats['total_unique_cookies']}
Unique main domains: {stats['unique_sites']}
Most common domain: {stats['most_common_site']}
Oldest cookies age: {stats.get('oldest_cookie_age', 'Unknown')}
Tracking cookies detected: {stats.get('tracking_intensity', 0)}
🏆 Privacy Score: {stats.get('privacy_score', 0.0)}/10.0
"""

        # Add categories section
        if categories:
            report_content += "\n=== BY CATEGORIES ===\n"
            for category, sites in categories.items():
                if sites:
                    report_content += f"{category.capitalize()}: {', '.join(sites)}\n"

        # Write the report to the cleaned file
        with open(temp_output, "w", encoding="utf-8") as f:
            f.write(report_content)

        # Send the report file
        await message.answer_document(
            FSInputFile(temp_output, filename=cleaned_filename),
            caption=f"Cleaned cookies report. Total kept: {stats['total_cleaned']}\n\nChoose an action:",
            reply_markup=keyboard
        )

        # Final status update without sending another message since keyboard is already sent with stats
        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text="✅ Processing complete!"
            )
        except Exception:
            pass  # Status message already updated

        processing_time.observe(time.time() - start_time)
        files_processed.inc()
        logger.info(f"Processed cookies for user {message.from_user.id}")

    except Exception as e:
        errors_total.labels(type="file_processing").inc()
        logger.error(f"Error processing file: {e}")
        keyboard = ReplyKeyboardMarkup(
            keyboard=[
                [KeyboardButton(text="🔄 Upload Another"), KeyboardButton(text="❌ Cancel")]
            ],
            resize_keyboard=True
        )
        try:
            await message.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=status_message_id,
                text=f"❌ Error: {str(e)}\n\nUpload another file or cancel:",
                reply_markup=keyboard
            )
        except Exception:
            await message.answer(f"Error processing file: {str(e)}\n\nChoose an action:", reply_markup=keyboard)
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


@router.message(F.text == "🕵️ OSINT")
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
