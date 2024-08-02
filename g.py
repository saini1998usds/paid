import telebot
import sqlite3
from datetime import datetime, timedelta
import subprocess
import threading
import logging
import time
from telebot import types

# Replace with your actual bot token
API_TOKEN = "7387781347:AAE5nhAsTCUT1v-ZL9ZMVSFJwyRK6IzEux4"
ADMIN_ID =7348590856

bot = telebot.TeleBot(API_TOKEN)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the database
def initialize_db():
    conn = sqlite3.connect('bot_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    status TEXT,
                    expire_date TEXT,
                    username TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    port INTEGER,
                    time INTEGER,
                    user_id INTEGER,
                    start_time TEXT,
                    end_time TEXT,
                    active INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT,
                    timestamp TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS user_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    command TEXT,
                    timestamp TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')

    conn.commit()
    conn.close()

# Add username column if it doesn't exist
def add_username_column():
    conn = sqlite3.connect('bot_data.db')
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE users ADD COLUMN username TEXT")
        conn.commit()
        logger.info("Column 'username' added successfully.")
    except sqlite3.OperationalError as e:
        logger.info(f"Column 'username' already exists: {e}")
    conn.close()

# Initialize and upgrade the database
initialize_db()
add_username_column()

# Helper function to add logs
def add_log(message):
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("INSERT INTO logs (message, timestamp) VALUES (?, ?)", (message, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error adding log: {e}")

def log_command(user_id, command):
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("INSERT INTO user_commands (user_id, command, timestamp) VALUES (?, ?, ?)",
                  (user_id, command, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error logging command: {e}")

def is_admin(user_id):
    return user_id == ADMIN_ID

def stop_attack(attack_id):
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("UPDATE attacks SET active = 0 WHERE id = ?", (attack_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error stopping attack: {e}")

def attack_thread(ip, port, attack_time, attack_id):
    try:
        start_time = time.time()
        command = f"python run_attack.py {ip} {port} {attack_time}"
        process = subprocess.Popen(command, shell=True)
        time.sleep(attack_time)  # Wait for attack time

        process.terminate()
        stop_attack(attack_id)
        end_time = time.time()
        add_log(f'Attack on IP {ip}, Port {port} has ended')

        bot.send_message(ADMIN_ID, f'Attack ended\nIP: {ip}\nPort: {port}\nTime: {end_time - start_time:.2f} seconds\nVERSION: BGMJ')
    except Exception as e:
        logger.error(f"Error in attack thread: {e}")

def update_approved_users_file():
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("SELECT id, username FROM users WHERE status = 'approved'")
        approved_users = c.fetchall()
        conn.close()

        with open('user.txt', 'w') as file:
            for user_id, username in approved_users:
                file.write(f'{user_id} {username}\n')
    except Exception as e:
        logger.error(f"Error updating user.txt: {e}")

@bot.message_handler(commands=['start'])
def start(message):
    user_id = message.from_user.id
    log_command(user_id, '/start')
    markup = types.ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
    markup.add(
        types.KeyboardButton('/approve'),
        types.KeyboardButton('/disapprove'),
        types.KeyboardButton('/check_all_user'),
        types.KeyboardButton('/check_on_going_attack'),
        types.KeyboardButton('/check_user_on_going_attack'),
        types.KeyboardButton('/show_all_user_information'),
        types.KeyboardButton('/attack'),
        types.KeyboardButton('/status'),
        types.KeyboardButton('/commands'),
        types.KeyboardButton('/Show_user_commands'),
        types.KeyboardButton('/Show_all_approved_users')
    )
    bot.send_message(message.chat.id, "Welcome! Use the commands below:", reply_markup=markup)

@bot.message_handler(commands=['approve'])
def approve(message):
    log_command(message.from_user.id, '/approve')
    if not is_admin(message.from_user.id):
        bot.reply_to(message, 'You are not authorized to use this command.')
        return

    args = message.text.split()
    if len(args) != 4:
        bot.reply_to(message, 'Usage: /approve <id> <days> <username>')
        return

    try:
        user_id = int(args[1])
        days = int(args[2])
        username = args[3]

        expire_date = datetime.now() + timedelta(days=days)

        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO users (id, status, expire_date, username) VALUES (?, 'approved', ?, ?)",
                  (user_id, expire_date.isoformat(), username))
        conn.commit()
        conn.close()

        update_approved_users_file()
        add_log(f'User {user_id} approved until {expire_date} with username {username}')
        bot.reply_to(message, f'User {user_id} approved until {expire_date} with username {username}')
    except Exception as e:
        logger.error(f"Error handling /approve command: {e}")

@bot.message_handler(commands=['disapprove'])
def disapprove(message):
    log_command(message.from_user.id, '/disapprove')
    if not is_admin(message.from_user.id):
        bot.reply_to(message, 'You are not authorized to use this command.')
        return

    args = message.text.split()
    if len(args) != 2:
        bot.reply_to(message, 'Usage: /disapprove <id>')
        return

    try:
        user_id = int(args[1])
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        update_approved_users_file()
        add_log(f'User {user_id} disapproved')
        bot.reply_to(message, f'User {user_id} disapproved')
    except Exception as e:
        logger.error(f"Error handling /disapprove command: {e}")

@bot.message_handler(commands=['check_all_user'])
def check_all_user(message):
    log_command(message.from_user.id, '/check_all_user')
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("SELECT id, status, expire_date, username FROM users")
        users = c.fetchall()
        conn.close()

        if not users:
            bot.reply_to(message, 'No users found')
            return

        user_info = '\n'.join([f'ID: {uid}, Status: {status}, Expire Date: {expire_date}, Username: {username}' for uid, status, expire_date, username in users])
        bot.reply_to(message, user_info)
    except Exception as e:
        logger.error(f"Error handling /check_all_user command: {e}")

@bot.message_handler(commands=['check_on_going_attack'])
def check_on_going_attack(message):
    log_command(message.from_user.id, '/check_on_going_attack')
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("SELECT id, ip, port, time, user_id FROM attacks WHERE active = 1")
        attacks = c.fetchall()
        conn.close()

        if not attacks:
            bot.reply_to(message, 'No ongoing attacks')
            return

        attack_info = '\n'.join([f'ID: {attack_id}, IP: {ip}, Port: {port}, Time: {time}, User ID: {user_id}' for attack_id, ip, port, time, user_id in attacks])
        bot.reply_to(message, attack_info)
    except Exception as e:
        logger.error(f"Error handling /check_on_going_attack command: {e}")

@bot.message_handler(commands=['check_user_on_going_attack'])
def check_user_on_going_attack(message):
    log_command(message.from_user.id, '/check_user_on_going_attack')
    args = message.text.split()
    if len(args) != 2:
        bot.reply_to(message, 'Usage: /check_user_on_going_attack <user_id>')
        return

    try:
        user_id = int(args[1])
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("SELECT id, ip, port, time, start_time FROM attacks WHERE user_id = ? AND active = 1", (user_id,))
        attacks = c.fetchall()
        conn.close()

        if not attacks:
            bot.reply_to(message, f'No ongoing attacks for user ID {user_id}')
            return

        attack_info = '\n'.join([f'ID: {attack_id}, IP: {ip}, Port: {port}, Time: {time}, Start Time: {start_time}' for attack_id, ip, port, time, start_time in attacks])
        bot.reply_to(message, attack_info)
    except Exception as e:
        logger.error(f"Error handling /check_user_on_going_attack command: {e}")

@bot.message_handler(commands=['show_all_user_information'])
def show_all_user_information(message):
    log_command(message.from_user.id, '/show_all_user_information')
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users")
        users = c.fetchall()
        conn.close()

        if not users:
            bot.reply_to(message, 'No user information found')
            return

        user_info = '\n'.join([f'ID: {id}, Status: {status}, Expire Date: {expire_date}, Username: {username}' for id, status, expire_date, username in users])
        bot.reply_to(message, user_info)
    except Exception as e:
        logger.error(f"Error handling /show_all_user_information command: {e}")

@bot.message_handler(commands=['attack'])
def attack(message):
    user_id = message.from_user.id
    log_command(user_id, '/attack')
    
    # Check if the user is approved
    conn = sqlite3.connect('bot_data.db')
    c = conn.cursor()
    c.execute("SELECT status FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    
    if not result or result[0] != 'approved':
        bot.reply_to(message, 'You are not authorized to use the /attack command.')
        return

    args = message.text.split()
    if len(args) != 4:
        bot.reply_to(message, 'Usage: /attack <ip> <port> <time>')
        return

    ip = args[1]
    port = int(args[2])
    attack_time = int(args[3])

    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("INSERT INTO attacks (ip, port, time, user_id, start_time, end_time, active) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (ip, port, attack_time, user_id, datetime.now().isoformat(), None, 1))
        attack_id = c.lastrowid
        conn.commit()
        conn.close()

        threading.Thread(target=attack_thread, args=(ip, port, attack_time, attack_id)).start()
        add_log(f'Started attack on IP {ip}, Port {port} by user {user_id}')
        bot.reply_to(message, f'Attack started on IP {ip}, Port {port} for {attack_time} seconds.')
    except Exception as e:
        logger.error(f"Error handling /attack command: {e}")

@bot.message_handler(commands=['status'])
def status(message):
    user_id = message.from_user.id
    log_command(user_id, '/status')
    
    conn = sqlite3.connect('bot_data.db')
    c = conn.cursor()
    c.execute("SELECT status, expire_date FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    if result:
        status, expire_date = result
        if expire_date and datetime.fromisoformat(expire_date) > datetime.now():
            bot.reply_to(message, f'Your status: {status}\nExpire Date: {expire_date}')
        else:
            bot.reply_to(message, 'Your status has expired or does not exist.')
    else:
        bot.reply_to(message, 'User not found.')

@bot.message_handler(commands=['commands'])
def commands(message):
    user_id = message.from_user.id
    log_command(user_id, '/commands')
    bot.reply_to(message, 'Available commands:\n'
                          '/approve <id> <days> <username> - Approve a user\n'
                          '/disapprove <id> - Disapprove a user\n'
                          '/check_all_user - Check all users\n'
                          '/check_on_going_attack - Check ongoing attacks\n'
                          '/check_user_on_going_attack <user_id> - Check ongoing attacks for a user\n'
                          '/show_all_user_information - Show all user information\n'
                          '/attack <ip> <port> <time> - Start an attack\n'
                          '/status - Check your status\n'
                          '/commands - List available commands\n'
                          '/Show_user_commands - Show user commands\n'
                          '/Show_all_approved_users - Show all approved users')

@bot.message_handler(commands=['Show_user_commands'])
def show_user_commands(message):
    user_id = message.from_user.id
    log_command(user_id, '/Show_user_commands')
    
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("SELECT command, timestamp FROM user_commands WHERE user_id = ?", (user_id,))
        commands = c.fetchall()
        conn.close()

        if not commands:
            bot.reply_to(message, 'No commands found for you.')
            return

        command_info = '\n'.join([f'Command: {command}, Timestamp: {timestamp}' for command, timestamp in commands])
        bot.reply_to(message, command_info)
    except Exception as e:
        logger.error(f"Error handling /Show_user_commands command: {e}")

@bot.message_handler(commands=['Show_all_approved_users'])
def show_all_approved_users(message):
    user_id = message.from_user.id
    log_command(user_id, '/Show_all_approved_users')
    
    try:
        conn = sqlite3.connect('bot_data.db')
        c = conn.cursor()
        c.execute("SELECT id, username FROM users WHERE status = 'approved'")
        approved_users = c.fetchall()
        conn.close()

        if not approved_users:
            bot.reply_to(message, 'No approved users found.')
            return

        user_info = '\n'.join([f'ID: {user_id}, Username: {username}' for user_id, username in approved_users])
        bot.reply_to(message, user_info)
    except Exception as e:
        logger.error(f"Error handling /Show_all_approved_users command: {e}")

bot.polling()
