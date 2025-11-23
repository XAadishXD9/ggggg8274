import discord
from discord.ext import commands
from discord import app_commands  # Import app_commands
import asyncio
import subprocess
import json
from datetime import datetime
import shlex
import logging
import shutil
import os
from typing import Optional, List, Dict, Any
import threading
import time
import random # <--- THÊM VÀO

# Load environment variables
DISCORD_TOKEN = ""
MAIN_ADMIN_ID = int(os.getenv('MAIN_ADMIN_ID', '1405778722732376176'))
VPS_USER_ROLE_ID = int(os.getenv('VPS_USER_ROLE_ID', '1405778722732376176'))
DEFAULT_STORAGE_POOL = os.getenv('DEFAULT_STORAGE_POOL', 'default')
CPU_THRESHOLD = int(os.getenv('CPU_THRESHOLD', '90'))
RAM_THRESHOLD = int(os.getenv('RAM_THRESHOLD', '90'))
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '600'))

# === PORT FORWARDING CONFIG ===
# Lấy địa chỉ IP public của máy chủ.
HOST_IP = os.getenv('HOST_IP') 
PORT_RANGE_START = 20000 # <--- Dải port ngẫu nhiên
PORT_RANGE_END = 60000   # <--- Dải port ngẫu nhiên
# ==============================

# Configure logging to file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('zx-nodes_bot')

# Check if lxc command is available
if not shutil.which("lxc"):
    logger.error("LXC command not found. Please ensure LXC is installed.")
    raise SystemExit("LXC command not found. Please ensure LXC is installed.")

# === PORT FORWARDING CHECK (UPDATED) ===
if not HOST_IP:
    logger.warning("HOST_IP environment variable is not set. Port forwarding features will be disabled.")
else:
    logger.info(f"Port forwarding enabled on HOST_IP: {HOST_IP}")
# =======================================

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

# Helper function to truncate text to a specific length
def truncate_text(text, max_length=1024):
    """Truncate text to max_length characters"""
    if not text:
        return text
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

# Embed creation functions with black theme and ZX-NODES branding
def create_embed(title, description="", color=0x1a1a1a):
    """Create a dark-themed embed with proper field length handling and ZX-NODES branding"""
    embed = discord.Embed(
        title=truncate_text(f"⭐ ZX-NODES - {title}", 256),
        description=truncate_text(description, 4096),
        color=color
    )

    embed.set_thumbnail(url="https://i.imgur.com/aQH8mZN.jpeg")
    embed.set_footer(text=f"ZX NODES VPS Manager • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                     icon_url="https://i.imgur.com/aQH8mZN.jpeg")

    return embed

def add_field(embed, name, value, inline=False):
    """Add a field to an embed with proper truncation"""
    embed.add_field(
        name=truncate_text(f"▸ {name}", 256),
        value=truncate_text(value, 1024),
        inline=inline
    )
    return embed

def create_success_embed(title, description=""):
    return create_embed(title, description, color=0x00ff88)

def create_error_embed(title, description=""):
    return create_embed(title, description, color=0xff3366)

def create_info_embed(title, description=""):
    return create_embed(title, description, color=0x00ccff)

def create_warning_embed(title, description=""):
    return create_embed(title, description, color=0xffaa00)

# Data storage functions
def load_vps_data():
    try:
        with open('vps_data.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning("vps_data.json not found or corrupted, initializing empty data")
        return {}

def load_admin_data():
    try:
        with open('admin_data.json', 'r') as f:
            data = json.load(f)
            # Đảm bảo các khóa cơ bản tồn tại
            if "admins" not in data:
                data["admins"] = [str(MAIN_ADMIN_ID)]
            if "status" not in data:
                data["status"] = {"type": "watching", "name": "ZX-NODES VPS Manager"}
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning("admin_data.json not found or corrupted, initializing with main admin")
        return {"admins": [str(MAIN_ADMIN_ID)], "status": {"type": "watching", "name": "ZX-NODES VPS Manager"}}

# === PORT FORWARDING DATA ===
def load_port_data():
    try:
        with open('port_data.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning("port_data.json not found, initializing empty data")
        # users: stores max port slots per user
        # forwards: stores active port forward rules
        return {"users": {}, "forwards": []}
# ============================

# Load all data at startup
vps_data = load_vps_data()
admin_data = load_admin_data()
port_data = load_port_data() # === PORT FORWARDING ===

# Save data function
def save_data():
    try:
        with open('vps_data.json', 'w') as f:
            json.dump(vps_data, f, indent=4)
        with open('admin_data.json', 'w') as f:
            json.dump(admin_data, f, indent=4)
        # === PORT FORWARDING ===
        with open('port_data.json', 'w') as f:
            json.dump(port_data, f, indent=4)
        # =======================
        logger.info("Data saved successfully")
    except Exception as e:
        logger.error(f"Error saving data: {e}")

# === FIX: Custom Command Tree for advanced error handling ===
class MyTree(app_commands.CommandTree):
    async def on_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        """Handle errors from slash commands"""
        if isinstance(error, app_commands.CommandNotFound):
            return  # This shouldn't really happen with slash commands
        
        elif isinstance(error, app_commands.CheckFailure):
            # Determine which check failed
            if "is_main_admin_check" in str(error):
                msg = "Only the main admin can use this command."
            else:
                msg = "You need admin permissions to use this command. Contact ZX-NODES support."
            
            if interaction.response.is_done():
                await interaction.followup.send(embed=create_error_embed("Access Denied", msg), ephemeral=True)
            else:
                await interaction.response.send_message(embed=create_error_embed("Access Denied", msg), ephemeral=True)
                
        elif isinstance(error, discord.NotFound):
            if interaction.response.is_done():
                await interaction.followup.send(embed=create_error_embed("Error", "The requested resource was not found. Please try again."), ephemeral=True)
            else:
                await interaction.response.send_message(embed=create_error_embed("Error", "The requested resource was not found. Please try again."), ephemeral=True)
                
        else:
            logger.error(f"App command error: {error}")
            error_embed = create_error_embed("System Error", "An unexpected error occurred. ZX-NODES support has been notified.")
            if interaction.response.is_done():
                await interaction.followup.send(embed=error_embed, ephemeral=True)
            else:
                await interaction.response.send_message(embed=error_embed, ephemeral=True)
# === End of FIX ===

# Disable the default help command
# === FIX: Use the custom tree_cls ===
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None, tree_cls=MyTree)
# === End of FIX ===

# CPU monitoring settings
cpu_monitor_active = True

# Admin checks - Updated for app_commands
def is_admin_check(interaction: discord.Interaction) -> bool:
    """Check if the user is a normal admin or main admin"""
    user_id = str(interaction.user.id)
    return user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])

def is_main_admin_check(interaction: discord.Interaction) -> bool:
    """Check if the user is the main admin"""
    return str(interaction.user.id) == str(MAIN_ADMIN_ID)

# Clean LXC command execution
async def execute_lxc(command, timeout=120):
    """Execute LXC command with timeout and error handling"""
    try:
        cmd = shlex.split(command)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode != 0:
            error = stderr.decode().strip() if stderr else "Command failed with no error output"
            raise Exception(error)

        return stdout.decode().strip() if stdout else True
    except asyncio.TimeoutError:
        logger.error(f"LXC command timed out: {command}")
        raise Exception(f"Command timed out after {timeout} seconds")
    except Exception as e:
        logger.error(f"LXC Error: {command} - {str(e)}")
        raise

# Get or create VPS user role
async def get_or_create_vps_role(guild):
    """Get or create the VPS User role"""
    global VPS_USER_ROLE_ID
    
    if VPS_USER_ROLE_ID:
        role = guild.get_role(VPS_USER_ROLE_ID)
        if role:
            return role
    
    role = discord.utils.get(guild.roles, name="ZX-NODES VPS User")
    if role:
        VPS_USER_ROLE_ID = role.id
        return role
    
    try:
        role = await guild.create_role(
            name="ZX-NODES VPS User",
            color=discord.Color.dark_purple(),
            reason="ZX-NODES VPS User role for bot management",
            permissions=discord.Permissions.none()
        )
        VPS_USER_ROLE_ID = role.id
        logger.info(f"Created ZX-NODES VPS User role: {role.name} (ID: {role.id})")
        return role
    except Exception as e:
        logger.error(f"Failed to create ZX-NODES VPS User role: {e}")
        return None

# Host CPU monitoring function
def get_cpu_usage():
    """Get current CPU usage percentage"""
    try:
        # Get CPU usage using top command
        result = subprocess.run(['top', '-bn1'], capture_output=True, text=True)
        output = result.stdout
        
        # Parse the output to get CPU usage
        for line in output.split('\n'):
            if '%Cpu(s):' in line:
                words = line.split()
                for i, word in enumerate(words):
                    if word == 'id,':
                        idle_str = words[i-1].rstrip(',')
                        try:
                            idle = float(idle_str)
                            usage = 100.0 - idle
                            return usage
                        except ValueError:
                            pass
                break
        return 0.0
    except Exception as e:
        logger.error(f"Error getting CPU usage: {e}")
        return 0.0

def cpu_monitor():
    """Monitor CPU usage and stop all VPS if threshold is exceeded"""
    global cpu_monitor_active
    
    while cpu_monitor_active:
        try:
            cpu_usage = get_cpu_usage()
            logger.info(f"Current CPU usage: {cpu_usage}%")
            
            if cpu_usage > CPU_THRESHOLD:
                logger.warning(f"CPU usage ({cpu_usage}%) exceeded threshold ({CPU_THRESHOLD}%). Stopping all VPS.")
                
                # Execute lxc stop --all --force
                try:
                    subprocess.run(['lxc', 'stop', '--all', '--force'], check=True)
                    logger.info("All VPS stopped due to high CPU usage")
                    
                    # Update all VPS status in database
                    for user_id, vps_list in vps_data.items():
                        for vps in vps_list:
                            if vps.get('status') == 'running':
                                vps['status'] = 'stopped'
                    save_data()
                except Exception as e:
                    logger.error(f"Error stopping all VPS: {e}")
            
            time.sleep(60)  # Check host every 60 seconds
        except Exception as e:
            logger.error(f"Error in CPU monitor: {e}")
            time.sleep(60)

# Start CPU monitoring in a separate thread
cpu_thread = threading.Thread(target=cpu_monitor, daemon=True)
cpu_thread.start()

# Helper functions for container stats
async def get_container_status(container_name):
    """Get the status of the LXC container"""
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "info", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        for line in output.splitlines():
            if line.startswith("Status: "):
                return line.split(": ", 1)[1].strip()
        return "Unknown"
    except Exception:
        return "Unknown"

async def get_container_cpu(container_name):
    """Get CPU usage inside the container as string"""
    usage = await get_container_cpu_pct(container_name)
    return f"{usage:.1f}%"

async def get_container_cpu_pct(container_name):
    """Get CPU usage percentage inside the container as float"""
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "top", "-bn1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        for line in output.splitlines():
            if '%Cpu(s):' in line:
                words = line.split()
                for i, word in enumerate(words):
                    if word == 'id,':
                        idle_str = words[i-1].rstrip(',')
                        try:
                            idle = float(idle_str)
                            usage = 100.0 - idle
                            return usage
                        except ValueError:
                            pass
                break
        return 0.0
    except Exception as e:
        logger.error(f"Error getting CPU for {container_name}: {e}")
        return 0.0

async def get_container_memory(container_name):
    """Get memory usage inside the container"""
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "free", "-m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        if len(lines) > 1:
            parts = lines[1].split()
            total = int(parts[1])
            used = int(parts[2])
            usage_pct = (used / total * 100) if total > 0 else 0
            return f"{used}/{total} MB ({usage_pct:.1f}%)"
        return "Unknown"
    except Exception:
        return "Unknown"

async def get_container_ram_pct(container_name):
    """Get RAM usage percentage inside the container as float"""
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "free", "-m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        if len(lines) > 1:
            parts = lines[1].split()
            total = int(parts[1])
            used = int(parts[2])
            usage_pct = (used / total * 100) if total > 0 else 0
            return usage_pct
        return 0.0
    except Exception as e:
        logger.error(f"Error getting RAM for {container_name}: {e}")
        return 0.0

async def get_container_disk(container_name):
    """Get disk usage inside the container"""
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "df", "-h", "/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        for line in lines:
            if '/dev/' in line and ' /' in line:
                parts = line.split()
                if len(parts) >= 5:
                    used = parts[2]
                    size = parts[1]
                    perc = parts[4]
                    return f"{used}/{size} ({perc})"
        return "Unknown"
    except Exception:
        return "Unknown"

def get_uptime():
    """Get host uptime"""
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return "Unknown"

# VPS monitoring task
async def vps_monitor():
    """Monitor each VPS for high CPU/RAM usage every 10 minutes"""
    await bot.wait_until_ready()  # Ensure bot is ready before starting loop
    while not bot.is_closed():
        try:
            for user_id, vps_list in vps_data.items():
                for vps in vps_list:
                    if vps.get('status') == 'running' and not vps.get('suspended', False):
                        container = vps['container_name']
                        cpu = await get_container_cpu_pct(container)
                        ram = await get_container_ram_pct(container)
                        if cpu > CPU_THRESHOLD or ram > RAM_THRESHOLD:
                            reason = f"High resource usage: CPU {cpu:.1f}%, RAM {ram:.1f}% (threshold: {CPU_THRESHOLD}% CPU / {RAM_THRESHOLD}% RAM)"
                            logger.warning(f"Suspending {container}: {reason}")
                            try:
                                await execute_lxc(f"lxc stop {container}")
                                vps['status'] = 'suspended'
                                vps['suspended'] = True
                                if 'suspension_history' not in vps:
                                    vps['suspension_history'] = []
                                vps['suspension_history'].append({
                                    'time': datetime.now().isoformat(),
                                    'reason': reason,
                                    'by': 'ZX-NODES Auto-System'
                                })
                                save_data()
                                # DM owner
                                try:
                                    owner = await bot.fetch_user(int(user_id))
                                    embed = create_warning_embed("🚨 VPS Auto-Suspended", f"Your VPS `{container}` has been automatically suspended due to high resource usage.\n\n**Reason:** {reason}\n\nContact ZX-NODES admin to unsuspend and address the issue.")
                                    await owner.send(embed=embed)
                                except Exception as dm_e:
                                    logger.error(f"Failed to DM owner {user_id}: {dm_e}")
                            except Exception as e:
                                logger.error(f"Failed to suspend {container}: {e}")
            await asyncio.sleep(CHECK_INTERVAL)
        except Exception as e:
            logger.error(f"VPS monitor error: {e}")
            await asyncio.sleep(60)

# === Helper function for setting status ===
async def set_bot_status(status_data: dict):
    """Sets the bot's presence based on a dictionary"""
    activity_name = status_data.get("name", "ZX-NODES VPS Manager")
    activity_type_str = status_data.get("type", "watching")
    
    activity_type_map = {
        "watching": discord.ActivityType.watching,
        "playing": discord.ActivityType.playing,
        "listening": discord.ActivityType.listening,
        "competing": discord.ActivityType.competing
    }
    
    activity_type = activity_type_map.get(activity_type_str.lower(), discord.ActivityType.watching)
    
    activity = discord.Activity(type=activity_type, name=activity_name)
    await bot.change_presence(activity=activity)
    logger.info(f"Bot status set to: {activity_type_str.capitalize()} {activity_name}")
# ========================================

# Bot events
@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    
    # === SET STATUS ON READY ===
    status_data = admin_data.get("status", {"type": "watching", "name": "ZX-NODES VPS Manager"})
    await set_bot_status(status_data)
    # ===========================
    
    # Sync slash commands
    try:
        synced = await bot.tree.sync()
        logger.info(f"Synced {len(synced)} slash commands")
    except Exception as e:
        logger.error(f"Failed to sync slash commands: {e}")
        
    asyncio.create_task(vps_monitor()) # Use asyncio.create_task
    logger.info("ZX-NODES Bot is ready! VPS monitoring started.")

# Bot commands
@bot.tree.command(name='ping', description="Check bot latency")
async def ping(interaction: discord.Interaction):
    """Check bot latency"""
    latency = round(bot.latency * 1000)
    embed = create_success_embed("Pong!", f"ZX-NODES Bot latency: {latency}ms")
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name='uptime', description="Show host uptime")
async def uptime(interaction: discord.Interaction):
    """Show host uptime"""
    up = get_uptime()
    embed = create_info_embed("Host Uptime", up)
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name='myvps', description="List your VPS")
async def my_vps(interaction: discord.Interaction):
    """List your VPS"""
    user_id = str(interaction.user.id)
    vps_list = vps_data.get(user_id, [])
    if not vps_list:
        await interaction.response.send_message(embed=create_embed("No VPS Found", "You don't have any ZX-NODES VPS. Contact an admin to create one.", 0xff3366))
        return
    embed = create_info_embed("My ZX-NODES VPS", "")
    text = []
    for i, vps in enumerate(vps_list):
        status = vps.get('status', 'unknown').upper()
        if vps.get('suspended', False):
            status += " (SUSPENDED)"
        config = vps.get('config', 'Custom')
        text.append(f"**VPS {i+1}:** `{vps['container_name']}` - {status} - {config}")
    add_field(embed, "Your VPS", "\n".join(text), False)
    add_field(embed, "Actions", "Use `/manage` to start/stop/reinstall", False)
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name='lxc-list', description="List all LXC containers (Admin only)")
@app_commands.check(is_admin_check)
async def lxc_list(interaction: discord.Interaction):
    """List all LXC containers"""
    try:
        result = await execute_lxc("lxc list")
        embed = create_info_embed("ZX-NODES LXC Containers List", result)
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        await interaction.response.send_message(embed=create_error_embed("Error", str(e)))

# === PASTE THIS ENTIRE BLOCK TO REPLACE YOUR OLD /create COMMAND ===
# This block includes:
# 1. The OS_IMAGES list (with the corrected Debian image paths)
# 2. The ImageSelectView class
# 3. The _perform_vps_creation helper function
# 4. The main create_vps command (with ephemeral=False)

# 1. OS Image Definitions (FIXED)
# Define the available OS images
OS_IMAGES = [
    discord.SelectOption(
        label="Ubuntu 22.04 (Jammy)",
        description="A stable, popular LTS release.",
        value="ubuntu:22.04",  # This is a valid alias
        emoji="🐧"
    ),
    discord.SelectOption(
        label="Ubuntu 24.04 (Noble)",
        description="The newest LTS release from Ubuntu.",
        value="ubuntu:24.04", # Assumes this alias is also valid
        emoji="🐧"
    ),
    discord.SelectOption(
        label="Ubuntu 20.04 (Focal)",
        description="An older, stable LTS release.",
        value="ubuntu:20.04", # Assumes this alias is also valid
        emoji="🐧"
    ),
    discord.SelectOption(
        label="Debian 12 (Bookworm)",
        description="The latest stable release from Debian.",
        value="images:debian/12",  # <-- FIXED
        emoji="📦"
    ),
    discord.SelectOption(
        label="Debian 11 (Bullseye)",
        description="An older, stable Debian release.",
        value="images:debian/11",  # <-- FIXED
        emoji="📦"
    ),
]


# 2. Image Selection View Class
class ImageSelectView(discord.ui.View):
    """
    This View presents a Select menu for the admin to choose an OS image.
    It's initiated by the /create command.
    """
    def __init__(self, ram: int, cpu: int, disk: int, user: discord.Member, original_interaction: discord.Interaction):
        super().__init__(timeout=180) # 3-minute timeout
        self.ram = ram
        self.cpu = cpu
        self.disk = disk
        self.user = user
        self.original_interaction = original_interaction # The /create command interaction

        # Define the select menu
        self.select_menu = discord.ui.Select(
            placeholder="Select an Operating System to install...",
            options=OS_IMAGES # Use the predefined list
        )
        
        # Assign the callback function
        self.select_menu.callback = self.image_select_callback
        self.add_item(self.select_menu)

    async def image_select_callback(self, interaction: discord.Interaction):
        """ This is called when the admin selects an OS from the menu. """
        
        # Security check: Only the user who ran /create can use this menu
        if interaction.user.id != self.original_interaction.user.id:
            await interaction.response.send_message("Only the admin who initiated the command can select an image.", ephemeral=True)
            return

        # Get the selected image (e.g., "images:debian/12")
        selected_image = self.select_menu.values[0]
        
        # Defer the interaction (for the "Creating..." message)
        await interaction.response.defer()
        
        # Disable the menu to prevent multiple clicks
        self.select_menu.disabled = True
        await self.original_interaction.edit_original_response(view=self)

        # Call the helper function to perform the actual creation
        await _perform_vps_creation(
            interaction=interaction, # Pass the NEW interaction (from the click)
            ram=self.ram,
            cpu=self.cpu,
            disk=self.disk,
            user=self.user,
            selected_image=selected_image
        )
    
    async def on_timeout(self):
        """Disables the view when 3 minutes have passed."""
        self.select_menu.disabled = True
        try:
            await self.original_interaction.edit_original_response(
                embed=create_error_embed("Command Timed Out", "You did not select an operating system in time. The command has been cancelled."),
                view=self
            )
        except discord.NotFound:
            pass # Message was likely deleted


# 3. Helper Function for VPS Creation
async def _perform_vps_creation(
    interaction: discord.Interaction, 
    ram: int, 
    cpu: int, 
    disk: int, 
    user: discord.Member, 
    selected_image: str
):
    """
    This function contains the actual LXC logic to create the VPS.
    It is called by the ImageSelectView after an image is chosen.
    """
    
    user_id = str(user.id)
    if user_id not in vps_data:
        vps_data[user_id] = []

    vps_count = len(vps_data[user_id]) + 1
    container_name = f"zx-nodes-{user_id}-{vps_count}"
    ram_mb = ram * 1024

    # Use followup.send() because the interaction was deferred
    await interaction.followup.send(embed=create_info_embed(
        "Creating ZX-NODES VPS", 
        f"Deploying {selected_image} VPS for {user.mention}..."
    ), ephemeral=True) # Send as ephemeral so only admin sees progress

    try:
        # === THIS LINE IS UPDATED TO USE THE SELECTED IMAGE ===
        await execute_lxc(f"lxc init {selected_image} {container_name} --storage {DEFAULT_STORAGE_POOL}")
        
        # Set resource limits (from your original code)
        await execute_lxc(f"lxc config set {container_name} limits.memory {ram_mb}MB")
        await execute_lxc(f"lxc config set {container_name} limits.cpu {cpu}")
        await execute_lxc(f"lxc config device set {container_name} root size {disk}GB")
        
        # [cite_start]Set security options (from your original code) [cite: 66-67]
        await execute_lxc(f"lxc config set {container_name} security.nesting true")
        await execute_lxc(f"lxc config set {container_name} raw.lxc 'lxc.apparmor.profile = unconfined'")
        await execute_lxc(f"lxc config set {container_name} security.privileged true")
        
        # Start the container
        await execute_lxc(f"lxc start {container_name}")

        # Add image to config string for easy identification
        config_str = f"{ram}GB RAM / {cpu} CPU / {disk}GB Disk ({selected_image})"
        
        # Store VPS info in the database
        vps_info = {
            "container_name": container_name,
            "ram": f"{ram}GB",
            "cpu": str(cpu),
            "storage": f"{disk}GB",
            "image": selected_image, # Store the image used
            "config": config_str,
            "status": "running",
            "suspended": False,
            "suspension_history": [],
            "created_at": datetime.now().isoformat(),
            "shared_with": [],
            "last_started_at": datetime.now().isoformat()
        }
        vps_data[user_id].append(vps_info)
        save_data() # Save to vps_data.json

        # Assign VPS role to the user
        if interaction.guild:
            vps_role = await get_or_create_vps_role(interaction.guild)
            if vps_role:
                try:
                    await user.add_roles(vps_role, reason="ZX-NODES VPS ownership granted")
                except discord.Forbidden:
                    logger.warning(f"Failed to assign ZX-NODES VPS role to {user.name}")

        # Send public success embed
        embed = create_success_embed("ZX-NODES VPS Created Successfully")
        add_field(embed, "Owner", user.mention, True)
        add_field(embed, "VPS ID", f"#{vps_count}", True)
        add_field(embed, "Container", f"`{container_name}`", True)
        add_field(embed, "OS Image", f"`{selected_image}`", True) # Added OS Image field
        add_field(embed, "Resources", f"**RAM:** {ram}GB\n**CPU:** {cpu} Cores\n**Storage:** {disk}GB", False)
        # Use followup.send() and make it public
        await interaction.followup.send(embed=embed, ephemeral=False)

        # Send comprehensive DM to user
        try:
            dm_embed = create_success_embed("ZX-NODES VPS Created!", f"Your VPS has been successfully deployed by an admin!")
            add_field(dm_embed, "VPS Details", f"**VPS ID:** #{vps_count}\n**Container Name:** `{container_name}`\n**OS Image:** `{selected_image}`\n**Configuration:** {config_str}\n**Status:** Running\n**Created:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", False)
            add_field(dm_embed, "Management", "• Use `/manage` to start/stop/reinstall your ZX-NODES VPS\n• Use `/manage` → SSH for terminal access\n• Contact ZX-NODES admin for upgrades or issues", False)
            add_field(dm_embed, "Important Notes", "• Full root access via SSH\n• Back up your data regularly with ZX-NODES tools", False)
            await user.send(embed=dm_embed)
        except discord.Forbidden:
            await interaction.followup.send(embed=create_info_embed("Notification Failed", f"Couldn't send DM to {user.mention}. [cite_start]Please ensure DMs are enabled."), ephemeral=True) [cite: 73-74]

    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Creation Failed", f"Error: {str(e)}"), ephemeral=True)


# 4. The new /create command (FIXED ephemeral=False)
@bot.tree.command(name='create', description="Create a custom VPS for a user (Admin only)")
@app_commands.describe(
    ram="RAM in GB",
    cpu="Number of CPU cores",
    disk="Disk size in GB",
    user="The user to create the VPS for"
)
@app_commands.check(is_admin_check)
async def create_vps(interaction: discord.Interaction, ram: int, cpu: int, disk: int, user: discord.Member):
    """Create a custom VPS for a user (Admin only) - /create <ram_gb> <cpu_cores> <disk_gb> <user>"""
    
    # Validate specs
    if ram <= 0 or cpu <= 0 or disk <= 0:
        await interaction.response.send_message(embed=create_error_embed("Invalid Specs", "RAM, CPU, and Disk must be positive integers."), ephemeral=True)
        return

    # Create the initial "Select OS" embed
    embed = create_info_embed(
        "Select Operating System",
        f"Please select an OS for {user.mention}'s new VPS.\n\n"
        f"**Specs:** {ram}GB RAM | {cpu} CPU | {disk}GB Disk"
    )
    
    # Create the View and pass the parameters to it
    view = ImageSelectView(
        ram=ram,
        cpu=cpu,
        disk=disk,
        user=user,
        original_interaction=interaction
    )
    
    # Send the message with the Select menu
    # === MODIFIED THIS LINE as requested ===
    await interaction.response.send_message(embed=embed, view=view, ephemeral=False)

# === END OF REPLACEMENT BLOCK ===

class ManageView(discord.ui.View):
    def __init__(self, user_id, vps_list, is_shared=False, owner_id=None, is_admin=False):
        super().__init__(timeout=300)
        self.user_id = user_id
        self.vps_list = vps_list
        self.selected_index = None
        self.is_shared = is_shared
        self.owner_id = owner_id or user_id
        self.is_admin = is_admin

        if len(vps_list) > 1:
            options = [
                discord.SelectOption(
                    label=f"ZX-NODES VPS {i+1} ({v.get('config', 'Custom')})",
                    description=f"Status: {v.get('status', 'unknown')}",
                    value=str(i)
                ) for i, v in enumerate(vps_list)
            ]
            self.select = discord.ui.Select(placeholder="Select a ZX-NODES VPS to manage", options=options)
            self.select.callback = self.select_vps
            self.add_item(self.select)
            self.initial_embed = create_embed("ZX-NODES VPS Management", "Select a VPS from the dropdown menu below.", 0x1a1a1a)
            add_field(self.initial_embed, "Available VPS", "\n".join([f"**VPS {i+1}:** `{v['container_name']}` - Status: `{v.get('status', 'unknown').upper()}`" for i, v in enumerate(vps_list)]), False)
        else:
            self.selected_index = 0
            self.initial_embed = None
            self.add_action_buttons()

    async def get_initial_embed(self):
        if self.initial_embed is not None:
            return self.initial_embed
        self.initial_embed = await self.create_vps_embed(self.selected_index)
        return self.initial_embed

    async def create_vps_embed(self, index):
        vps = self.vps_list[index]
        status = vps.get('status', 'unknown')
        suspended = vps.get('suspended', False)
        status_color = 0x00ff88 if status == 'running' and not suspended else 0xffaa00 if suspended else 0xff3366

        # Fetch live stats
        container_name = vps['container_name']
        lxc_status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)

        status_text = f"{status.upper()}"
        if suspended:
            status_text += " (SUSPENDED)"

        owner_text = ""
        if self.is_admin and self.owner_id != self.user_id:
            try:
                owner_user = bot.get_user(int(self.owner_id))
                owner_text = f"\n**Owner:** {owner_user.mention}"
            except:
                owner_text = f"\n**Owner ID:** {self.owner_id}"

        embed = create_embed(
            f"ZX-NODES VPS Management - VPS {index + 1}",
            f"Managing container: `{container_name}`{owner_text}",
            status_color
        )

        resource_info = f"**Configuration:** {vps.get('config', 'Custom')}\n"
        resource_info += f"**Status:** `{status_text}`\n"
        resource_info += f"**RAM:** {vps['ram']}\n"
        resource_info += f"**CPU:** {vps['cpu']} Cores\n"
        resource_info += f"**Storage:** {vps['storage']}"

        # --- TÍNH TOÁN VÀ THÊM UPTIME ---
        uptime_str = "Offline"
        if status == 'running' and not suspended:
            if 'last_started_at' in vps:
                try:
                    start_time = datetime.fromisoformat(vps['last_started_at'])
                    uptime_delta = datetime.now() - start_time
                    days, remainder = divmod(uptime_delta.total_seconds(), 86400)
                    hours, remainder = divmod(remainder, 3600)
                    minutes, _ = divmod(remainder, 60)
                    uptime_str = f"{int(days)}d {int(hours)}h {int(minutes)}m"
                except (ValueError, TypeError):
                    uptime_str = "Unknown"
        resource_info += f"\n**Uptime:** {uptime_str}"
        # ------------------------------------

        add_field(embed, "📊 Allocated Resources", resource_info, False)

        if suspended:
            add_field(embed, "⚠️ Suspended", "This ZX-NODES VPS is suspended. Contact an admin to unsuspend.", False)

        live_stats = f"**CPU Usage:** {cpu_usage}\n**Memory:** {memory_usage}\n**Disk:** {disk_usage}"
        add_field(embed, "📈 Live Usage", live_stats, False)

        add_field(embed, "🎮 Controls", "Use the buttons below to manage your ZX-NODES VPS", False)

        return embed

    def add_action_buttons(self):
        if not self.is_shared and not self.is_admin:
            reinstall_button = discord.ui.Button(label="🔄 Reinstall", style=discord.ButtonStyle.danger)
            reinstall_button.callback = lambda inter: self.action_callback(inter, 'reinstall')
            self.add_item(reinstall_button)

        start_button = discord.ui.Button(label="▶ Start", style=discord.ButtonStyle.success)
        start_button.callback = lambda inter: self.action_callback(inter, 'start')
        stop_button = discord.ui.Button(label="⏸ Stop", style=discord.ButtonStyle.secondary)
        stop_button.callback = lambda inter: self.action_callback(inter, 'stop')
        ssh_button = discord.ui.Button(label="🔑 SSH", style=discord.ButtonStyle.primary)
        ssh_button.callback = lambda inter: self.action_callback(inter, 'tmate')
        stats_button = discord.ui.Button(label="📊 Stats", style=discord.ButtonStyle.secondary)
        stats_button.callback = lambda inter: self.action_callback(inter, 'stats')

        self.add_item(start_button)
        self.add_item(stop_button)
        self.add_item(ssh_button)
        self.add_item(stats_button)

    async def select_vps(self, interaction: discord.Interaction):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This is not your ZX-NODES VPS!"), ephemeral=True)
            return
        self.selected_index = int(self.select.values[0])
        new_embed = await self.create_vps_embed(self.selected_index)
        self.clear_items()
        self.add_action_buttons()
        await interaction.response.edit_message(embed=new_embed, view=self)

    async def action_callback(self, interaction: discord.Interaction, action: str):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This is not your ZX-NODES VPS!"), ephemeral=True)
            return

        if self.is_shared:
            vps = vps_data[self.owner_id][self.selected_index]
        else:
            vps = self.vps_list[self.selected_index]
        
        suspended = vps.get('suspended', False)
        if suspended and not self.is_admin and action != 'stats':
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This ZX-NODES VPS is suspended. Contact an admin to unsuspend."), ephemeral=True)
            return
        
        container_name = vps["container_name"]

        if action == 'stats':
            status = await get_container_status(container_name)
            cpu_usage = await get_container_cpu(container_name)
            memory_usage = await get_container_memory(container_name)
            disk_usage = await get_container_disk(container_name)
            stats_embed = create_info_embed("📈 ZX-NODES Live Statistics", f"Real-time stats for `{container_name}`")
            add_field(stats_embed, "Status", f"`{status.upper()}`", True)
            add_field(stats_embed, "CPU", cpu_usage, True)
            add_field(stats_embed, "Memory", memory_usage, True)
            add_field(stats_embed, "Disk", disk_usage, True)
            await interaction.response.send_message(embed=stats_embed, ephemeral=True)
            return

        if action == 'reinstall':
            if self.is_shared or self.is_admin:
                await interaction.response.send_message(embed=create_error_embed("Access Denied", "Only the ZX-NODES VPS owner can reinstall!"), ephemeral=True)
                return
            if suspended:
                await interaction.response.send_message(embed=create_error_embed("Cannot Reinstall", "Unsuspend the ZX-NODES VPS first."), ephemeral=True)
                return

            confirm_embed = create_warning_embed("ZX-NODES Reinstall Warning",
                f"⚠️ **WARNING:** This will erase all data on VPS `{container_name}` and reinstall Ubuntu 22.04.\n\n"
                f"This action cannot be undone. Continue?")

            class ConfirmView(discord.ui.View):
                def __init__(self, parent_view, container_name, vps, owner_id, selected_index):
                    super().__init__(timeout=60)
                    self.parent_view = parent_view
                    self.container_name = container_name
                    self.vps = vps
                    self.owner_id = owner_id
                    self.selected_index = selected_index

                @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger)
                async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
                    await interaction.response.defer(ephemeral=True)
                    try:
                        # Force delete the container first
                        await interaction.followup.send(embed=create_info_embed("Deleting Container", f"Forcefully removing container `{self.container_name}`..."), ephemeral=True)
                        await execute_lxc(f"lxc delete {self.container_name} --force")

                        # Recreate with original specifications - Fixed init + start
                        await interaction.followup.send(embed=create_info_embed("Recreating Container", f"Creating new ZX-NODES container `{self.container_name}`..."), ephemeral=True)
                        original_ram = self.vps["ram"]
                        original_cpu = self.vps["cpu"]
                        original_storage = self.vps["storage"]
                        ram_gb = int(original_ram.replace("GB", ""))
                        ram_mb = ram_gb * 1024
                        cpu_cores = int(original_cpu)
                        storage_gb = int(original_storage.replace("GB", ""))

                        await execute_lxc(f"lxc init ubuntu:22.04 {self.container_name} --storage {DEFAULT_STORAGE_POOL}")
                        await execute_lxc(f"lxc config set {self.container_name} limits.memory {ram_mb}MB")
                        await execute_lxc(f"lxc config set {self.container_name} limits.cpu {original_cpu}")
                        await execute_lxc(f"lxc config device set {self.container_name} root size {storage_gb}GB")
                        await execute_lxc(f"lxc start {self.container_name}")

                        self.vps["status"] = "running"
                        self.vps["suspended"] = False
                        self.vps["last_started_at"] = datetime.now().isoformat()
                        self.vps["created_at"] = datetime.now().isoformat()
                        config_str = f"{ram_gb}GB RAM / {cpu_cores} CPU / {storage_gb}GB Disk"
                        self.vps["config"] = config_str
                        save_data()
                        await interaction.followup.send(embed=create_success_embed("Reinstall Complete", f"ZX-NODES VPS `{self.container_name}` has been successfully reinstalled!"), ephemeral=True)

                        # Edit the original message if possible, but since ephemeral, send updated embed as followup
                        new_embed = await self.parent_view.create_vps_embed(self.parent_view.selected_index)
                        await interaction.followup.send(embed=new_embed, ephemeral=True)

                    except Exception as e:
                        await interaction.followup.send(embed=create_error_embed("Reinstall Failed", f"Error: {str(e)}"), ephemeral=True)

                @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
                async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
                    new_embed = await self.parent_view.create_vps_embed(self.parent_view.selected_index)
                    await interaction.response.edit_message(embed=new_embed, view=self.parent_view)

            await interaction.response.send_message(embed=confirm_embed, view=ConfirmView(self, container_name, vps, self.owner_id, self.selected_index), ephemeral=True)

        elif action == 'start':
            await interaction.response.defer(ephemeral=True)
            if suspended:
                vps['suspended'] = False
                save_data()
            try:
                await execute_lxc(f"lxc start {container_name}")
                vps["status"] = "running"
                vps["last_started_at"] = datetime.now().isoformat()
                save_data()
                await interaction.followup.send(embed=create_success_embed("VPS Started", f"ZX-NODES VPS `{container_name}` is now running!"), ephemeral=True)
                new_embed = await self.create_vps_embed(self.selected_index)
                await interaction.message.edit(embed=new_embed, view=self)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Start Failed", str(e)), ephemeral=True)

        elif action == 'stop':
            await interaction.response.defer(ephemeral=True)
            if suspended:
                vps['suspended'] = False
                save_data()
            try:
                await execute_lxc(f"lxc stop {container_name}", timeout=120)
                vps["status"] = "stopped"
                save_data()
                await interaction.followup.send(embed=create_success_embed("VPS Stopped", f"ZX-NODES VPS `{container_name}` has been stopped!"), ephemeral=True)
                new_embed = await self.create_vps_embed(self.selected_index)
                await interaction.message.edit(embed=new_embed, view=self)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Stop Failed", str(e)), ephemeral=True)

        elif action == 'tmate':
            if suspended:
                await interaction.response.send_message(embed=create_error_embed("Access Denied", "Cannot access suspended ZX-NODES VPS."), ephemeral=True)
                return
            await interaction.response.send_message(embed=create_info_embed("SSH Access", "Generating ZX-NODES SSH connection..."), ephemeral=True)

            try:
                # Check if tmate exists
                check_proc = await asyncio.create_subprocess_exec(
                    "lxc", "exec", container_name, "--", "which", "tmate",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await check_proc.communicate()

                if check_proc.returncode != 0:
                    await interaction.followup.send(embed=create_info_embed("Installing SSH", "Installing tmate..."), ephemeral=True)
                    await execute_lxc(f"lxc exec {container_name} -- sudo apt-get update -y")
                    await execute_lxc(f"lxc exec {container_name} -- sudo apt-get install tmate -y")
                    await interaction.followup.send(embed=create_success_embed("Installed", "ZX-NODES SSH service installed!"), ephemeral=True)

                # Start tmate with unique session name using timestamp
                session_name = f"zx-nodes-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                await execute_lxc(f"lxc exec {container_name} -- tmate -S /tmp/{session_name}.sock new-session -d")
                await asyncio.sleep(3)

                # Get SSH link
                ssh_proc = await asyncio.create_subprocess_exec(
                    "lxc", "exec", container_name, "--", "tmate", "-S", f"/tmp/{session_name}.sock", "display", "-p", "#{tmate_ssh}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await ssh_proc.communicate()
                ssh_url = stdout.decode().strip() if stdout else None

                if ssh_url:
                    try:
                        ssh_embed = create_embed("🔑 ZX-NODES SSH Access", f"SSH connection for VPS `{container_name}`:", 0x00ff88)
                        add_field(ssh_embed, "Command", f"```{ssh_url}```", False)
                        add_field(ssh_embed, "⚠️ Security", "This link is temporary. Do not share it.", False)
                        add_field(ssh_embed, "📝 Session", f"Session ID: {session_name}", False)
                        await interaction.user.send(embed=ssh_embed)
                        await interaction.followup.send(embed=create_success_embed("SSH Sent", f"Check your DMs for ZX-NODES SSH link! Session: {session_name}"), ephemeral=True)
                    except discord.Forbidden:
                        await interaction.followup.send(embed=create_error_embed("DM Failed", "Enable DMs to receive ZX-NODES SSH link!"), ephemeral=True)
                else:
                    error_msg = stderr.decode().strip() if stderr else "Unknown error"
                    await interaction.followup.send(embed=create_error_embed("SSH Failed", error_msg), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("SSH Error", str(e)), ephemeral=True)

@bot.tree.command(name='manage', description="Manage your ZX-NODES VPS or another user's VPS (Admin only)")
@app_commands.describe(user="[Admin only] The user whose VPS you want to manage")
async def manage_vps(interaction: discord.Interaction, user: Optional[discord.Member] = None):
    """Manage your ZX-NODES VPS or another user's VPS (Admin only)"""
    # Check if user is trying to manage someone else's VPS
    if user:
        # Only admins can manage other users' VPS
        user_id_check = str(interaction.user.id)
        if user_id_check != str(MAIN_ADMIN_ID) and user_id_check not in admin_data.get("admins", []):
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "Only ZX-NODES admins can manage other users' VPS."), ephemeral=True)
            return
        
        user_id = str(user.id)
        vps_list = vps_data.get(user_id, [])
        if not vps_list:
            await interaction.response.send_message(embed=create_error_embed("No VPS Found", f"{user.mention} doesn't have any ZX-NODES VPS."), ephemeral=True)
            return
        
        # Create admin view for managing another user's VPS
        view = ManageView(str(interaction.user.id), vps_list, is_admin=True, owner_id=user_id)
        await interaction.response.send_message(embed=create_info_embed(f"Managing {user.name}'s ZX-NODES VPS", f"Managing VPS for {user.mention}"), view=view)
    else:
        # User managing their own VPS
        user_id = str(interaction.user.id)
        vps_list = vps_data.get(user_id, [])
        if not vps_list:
            embed = create_embed("No VPS Found", "You don't have any ZX-NODES VPS. Contact an admin to create one.", 0xff3366)
            add_field(embed, "Quick Actions", "• `/manage` - Manage VPS\n• Contact ZX-NODES admin for VPS creation", False)
            await interaction.response.send_message(embed=embed)
            return
        view = ManageView(user_id, vps_list)
        embed = await view.get_initial_embed()
        await interaction.response.send_message(embed=embed, view=view)

@bot.tree.command(name='list-all', description="List all ZX-NODES VPS and user information (Admin only)")
@app_commands.check(is_admin_check)
async def list_all_vps(interaction: discord.Interaction):
    """List all ZX-NODES VPS and user information (Admin only)"""
    await interaction.response.defer() # This command can be long
    
    total_vps = 0
    total_users = len(vps_data)
    running_vps = 0
    stopped_vps = 0
    suspended_vps = 0
    
    vps_info = []
    user_summary = []
    
    for user_id, vps_list in vps_data.items():
        try:
            user = await bot.fetch_user(int(user_id))
            user_vps_count = len(vps_list)
            user_running = sum(1 for vps in vps_list if vps.get('status') == 'running' and not vps.get('suspended', False))
            user_stopped = sum(1 for vps in vps_list if vps.get('status') == 'stopped')
            user_suspended = sum(1 for vps in vps_list if vps.get('suspended', True))
            
            total_vps += user_vps_count
            running_vps += user_running
            stopped_vps += user_stopped
            suspended_vps += user_suspended
            
            # User summary
            user_summary.append(f"**{user.name}** ({user.mention}) - {user_vps_count} ZX-NODES VPS ({user_running} running, {user_suspended} suspended)")
            
            # Individual VPS details
            for i, vps in enumerate(vps_list):
                status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
                status_text = vps.get('status', 'unknown').upper()
                if vps.get('suspended', False):
                    status_text += " (SUSPENDED)"
                vps_info.append(f"{status_emoji} **{user.name}** - VPS {i+1}: `{vps['container_name']}` - {vps.get('config', 'Custom')} - {status_text}")
                
        except discord.NotFound:
            vps_info.append(f"❓ Unknown User ({user_id}) - {len(vps_list)} ZX-NODES VPS")
    
    # Create multiple embeds if needed to avoid character limit
    embeds_to_send = []
    
    # First embed with overview
    embed = create_embed("All ZX-NODES VPS Information", "Complete overview of all ZX-NODES VPS deployments and user statistics", 0x1a1a1a)
    add_field(embed, "System Overview", f"**Total Users:** {total_users}\n**Total VPS:** {total_vps}\n**Running:** {running_vps}\n**Stopped:** {stopped_vps}\n**Suspended:** {suspended_vps}", False)
    embeds_to_send.append(embed)
    
    # User summary embed
    if user_summary:
        embed = create_embed("ZX-NODES User Summary", f"Summary of all users and their ZX-NODES VPS", 0x1a1a1a)
        # Split user summary into chunks to avoid character limit
        for i in range(0, len(user_summary), 10):
            chunk = user_summary[i:i+10]
            summary_text = "\n".join(chunk)
            if i == 0:
                add_field(embed, "Users", summary_text, False)
            else:
                add_field(embed, f"Users (continued {i+1}-{min(i+10, len(user_summary))})", summary_text, False)
        embeds_to_send.append(embed)
    
    # VPS details embeds
    if vps_info:
        # Split VPS info into chunks to avoid character limit
        for i in range(0, len(vps_info), 15):
            chunk = vps_info[i:i+15]
            embed = create_embed(f"ZX-NODES VPS Details ({i+1}-{min(i+15, len(vps_info))})", "List of all ZX-NODES VPS deployments", 0x1a1a1a)
            add_field(embed, "VPS List", "\n".join(chunk), False)
            embeds_to_send.append(embed)
    
    # Send all embeds
    await interaction.followup.send(embed=embeds_to_send[0])
    for embed in embeds_to_send[1:]:
        await interaction.followup.send(embed=embed)

@bot.tree.command(name='manage-shared', description="Manage a shared ZX-NODES VPS")
@app_commands.describe(owner="The owner of the VPS", vps_number="The VPS number (e.g., 1)")
async def manage_shared_vps(interaction: discord.Interaction, owner: discord.Member, vps_number: int):
    """Manage a shared ZX-NODES VPS"""
    owner_id = str(owner.id)
    user_id = str(interaction.user.id)
    if owner_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[owner_id]):
        await interaction.response.send_message(embed=create_error_embed("Invalid VPS", "Invalid VPS number or owner doesn't have a ZX-NODES VPS."), ephemeral=True)
        return
    vps = vps_data[owner_id][vps_number - 1]
    if user_id not in vps.get("shared_with", []):
        await interaction.response.send_message(embed=create_error_embed("Access Denied", "You do not have access to this ZX-NODES VPS."), ephemeral=True)
        return
    view = ManageView(user_id, [vps], is_shared=True, owner_id=owner_id)
    embed = await view.get_initial_embed()
    await interaction.response.send_message(embed=embed, view=view)

@bot.tree.command(name='share-user', description="Share ZX-NODES VPS access with another user")
@app_commands.describe(shared_user="The user to share with", vps_number="Your VPS number to share")
async def share_user(interaction: discord.Interaction, shared_user: discord.Member, vps_number: int):
    """Share ZX-NODES VPS access with another user"""
    user_id = str(interaction.user.id)
    shared_user_id = str(shared_user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await interaction.response.send_message(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a ZX-NODES VPS."), ephemeral=True)
        return
    vps = vps_data[user_id][vps_number - 1]

    if "shared_with" not in vps:
        vps["shared_with"] = []

    if shared_user_id in vps["shared_with"]:
        await interaction.response.send_message(embed=create_error_embed("Already Shared", f"{shared_user.mention} already has access to this ZX-NODES VPS!"), ephemeral=True)
        return
    vps["shared_with"].append(shared_user_id)
    save_data()
    await interaction.response.send_message(embed=create_success_embed("VPS Shared", f"ZX-NODES VPS #{vps_number} shared with {shared_user.mention}!"))
    try:
        await shared_user.send(embed=create_embed("ZX-NODES VPS Access Granted", f"You have access to VPS #{vps_number} from {interaction.user.mention}. Use `/manage-shared owner:{interaction.user.mention} vps_number:{vps_number}`", 0x00ff88))
    except discord.Forbidden:
        await interaction.followup.send(embed=create_info_embed("Notification Failed", f"Could not DM {shared_user.mention}"), ephemeral=True)

@bot.tree.command(name='share-ruser', description="Revoke shared ZX-NODES VPS access")
@app_commands.describe(shared_user="The user to revoke access from", vps_number="Your VPS number")
async def revoke_share(interaction: discord.Interaction, shared_user: discord.Member, vps_number: int):
    """Revoke shared ZX-NODES VPS access"""
    user_id = str(interaction.user.id)
    shared_user_id = str(shared_user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await interaction.response.send_message(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a ZX-NODES VPS."), ephemeral=True)
        return
    vps = vps_data[user_id][vps_number - 1]

    if "shared_with" not in vps:
        vps["shared_with"] = []

    if shared_user_id not in vps["shared_with"]:
        await interaction.response.send_message(embed=create_error_embed("Not Shared", f"{shared_user.mention} doesn't have access to this ZX-NODES VPS!"), ephemeral=True)
        return
    vps["shared_with"].remove(shared_user_id)
    save_data()
    await interaction.response.send_message(embed=create_success_embed("Access Revoked", f"Access to ZX-NODES VPS #{vps_number} revoked from {shared_user.mention}!"))
    try:
        await shared_user.send(embed=create_embed("ZX-NODES VPS Access Revoked", f"Your access to VPS #{vps_number} by {interaction.user.mention} has been revoked.", 0xff3366))
    except discord.Forbidden:
        await interaction.followup.send(embed=create_info_embed("Notification Failed", f"Could not DM {shared_user.mention}"), ephemeral=True)

@bot.tree.command(name='delete-vps', description="Delete a user's ZX-NODES VPS (Admin only)")
@app_commands.describe(user="The user whose VPS to delete", vps_number="The VPS number", reason="Reason for deletion")
@app_commands.check(is_admin_check)
async def delete_vps(interaction: discord.Interaction, user: discord.Member, vps_number: int, reason: str = "No reason"):
    """Delete a user's ZX-NODES VPS (Admin only)"""
    user_id = str(user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await interaction.response.send_message(embed=create_error_embed("Invalid VPS", "Invalid VPS number or user doesn't have a ZX-NODES VPS."), ephemeral=True)
        return
    vps = vps_data[user_id][vps_number - 1]
    container_name = vps["container_name"]

    await interaction.response.send_message(embed=create_info_embed("Deleting ZX-NODES VPS", f"Removing VPS #{vps_number}..."))

    try:
        await execute_lxc(f"lxc delete {container_name} --force")
        del vps_data[user_id][vps_number - 1]
        if not vps_data[user_id]:
            del vps_data[user_id]
            # Remove VPS role if user has no more VPS
            if interaction.guild:
                vps_role = await get_or_create_vps_role(interaction.guild)
                if vps_role and vps_role in user.roles:
                    try:
                        await user.remove_roles(vps_role, reason="No ZX-NODES VPS ownership")
                    except discord.Forbidden:
                        logger.warning(f"Failed to remove ZX-NODES VPS role from {user.name}")
        save_data()

        embed = create_success_embed("ZX-NODES VPS Deleted Successfully")
        add_field(embed, "Owner", user.mention, True)
        add_field(embed, "VPS ID", f"#{vps_number}", True)
        add_field(embed, "Container", f"`{container_name}`", True)
        add_field(embed, "Reason", reason, False)
        await interaction.followup.send(embed=embed)
        
        # === PORT FORWARDING CLEANUP ===
        if HOST_IP: # Only run if ports are enabled
            ports_to_remove = [f for f in port_data["forwards"] if f["container_name"] == container_name]
            if ports_to_remove:
                logger.info(f"Cleaning up {len(ports_to_remove)} port forwards for deleted container {container_name}")
                port_data["forwards"] = [f for f in port_data["forwards"] if f["container_name"] != container_name]
                save_data()
        # ===============================

    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Deletion Failed", f"Error: {str(e)}"))

class ConfirmDeleteSomeView(discord.ui.View):
    """A view to confirm the deletion of multiple VPS."""
    def __init__(self, user: discord.Member, containers_to_delete: List[str]):
        super().__init__(timeout=60)
        self.user = user
        self.containers_to_delete = containers_to_delete

    @discord.ui.button(label="Confirm Deletion", style=discord.ButtonStyle.danger)
    async def confirm_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Vô hiệu hóa các nút ngay lập tức để tránh nhấn nhiều lần
        for item in self.children:
            item.disabled = True
        
        # Gửi phản hồi ban đầu để người dùng biết yêu cầu đang được xử lý
        await interaction.response.edit_message(
            embed=create_info_embed("Processing Deletion", "Please wait while the selected VPS are being deleted..."), view=self
        )
        deleted_containers = []
        failed_containers = []
        
        for container_name in self.containers_to_delete:
            try:
                await execute_lxc(f"lxc delete {container_name} --force")
                deleted_containers.append(f"`{container_name}`")
            except Exception as e:
                logger.error(f"Failed to delete container {container_name}: {e}")
                failed_containers.append(f"`{container_name}`")

        # Update vps_data.json
        user_id = str(self.user.id)
        if user_id in vps_data:
            vps_data[user_id] = [vps for vps in vps_data[user_id] if vps['container_name'] not in self.containers_to_delete]
            if not vps_data[user_id]:
                del vps_data[user_id]
        
        # Update port_data.json
        if HOST_IP:
            port_data["forwards"] = [fwd for fwd in port_data["forwards"] if fwd['container_name'] not in self.containers_to_delete]

        save_data()

        # Send final report
        report_embed = create_success_embed("Deletion Report", f"Deletion process completed for {self.user.mention}.")
        if deleted_containers:
            add_field(report_embed, "✅ Successfully Deleted", "\n".join(deleted_containers), False)
        if failed_containers:
            add_field(report_embed, "❌ Failed to Delete", "\n".join(failed_containers), False)
        
        # Gửi báo cáo cuối cùng dưới dạng một tin nhắn mới
        await interaction.followup.send(embed=report_embed, ephemeral=True)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Vô hiệu hóa các nút
        for item in self.children:
            item.disabled = True
        
        # Chỉnh sửa tin nhắn để thông báo đã hủy
        await interaction.response.edit_message(
            embed=create_info_embed("Cancelled", "The deletion process has been cancelled."), view=self)

class DeleteVpsSomeView(discord.ui.View):
    """A view with a multi-select dropdown to choose VPS for deletion."""
    def __init__(self, user: discord.Member, vps_list: List[Dict[str, Any]], original_interaction: discord.Interaction):
        super().__init__(timeout=300)
        self.user = user
        self.original_interaction = original_interaction
        self.selected_containers: List[str] = []

        options = [
            discord.SelectOption(
                label=f"VPS {i+1}: {vps['container_name']}",
                description=vps.get('config', 'Custom Config'),
                value=vps['container_name']
            ) for i, vps in enumerate(vps_list)
        ]

        self.select_menu = discord.ui.Select(
            placeholder="Select one or more VPS to delete...",
            min_values=1,
            max_values=len(options),
            options=options
        )
        self.select_menu.callback = self.select_callback
        self.add_item(self.select_menu)

    async def select_callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.original_interaction.user.id:
            return await interaction.response.send_message("You cannot use this menu.", ephemeral=True)

        self.selected_containers = self.select_menu.values
        
        confirm_embed = create_warning_embed(
            "Confirm Deletion",
            f"You are about to permanently delete the following **{len(self.selected_containers)}** VPS for {self.user.mention}:\n\n" +
            "\n".join([f"• `{name}`" for name in self.selected_containers]) +
            "\n\n**This action cannot be undone.**"
        )
        
        confirm_view = ConfirmDeleteSomeView(self.user, self.selected_containers)
        await interaction.response.send_message(embed=confirm_embed, view=confirm_view, ephemeral=True)

@bot.tree.command(name='add-resources', description="Add resources to a ZX-NODES VPS (Admin only)")
@app_commands.describe(
    vps_id="The container name (e.g., zx-nodes-123-1)",
    ram="GB of RAM to add",
    cpu="Number of CPU cores to add",
    disk="GB of disk space to add"
)
@app_commands.check(is_admin_check)
async def add_resources(interaction: discord.Interaction, vps_id: str, ram: Optional[int] = None, cpu: Optional[int] = None, disk: Optional[int] = None):
    """Add resources to a ZX-NODES VPS (Admin only)"""
    if ram is None and cpu is None and disk is None:
        await interaction.response.send_message(embed=create_error_embed("Missing Parameters", "Please specify at least one resource to add (ram, cpu, or disk)"), ephemeral=True)
        return
    
    # Find the VPS in our database
    found_vps = None
    user_id = None
    vps_index = None
    
    for uid, vps_list in vps_data.items():
        for i, vps in enumerate(vps_list):
            if vps['container_name'] == vps_id:
                found_vps = vps
                user_id = uid
                vps_index = i
                break
        if found_vps:
            break
    
    if not found_vps:
        await interaction.response.send_message(embed=create_error_embed("VPS Not Found", f"No ZX-NODES VPS found with ID: `{vps_id}`"), ephemeral=True)
        return
    
    await interaction.response.defer() # This may take time
    
    was_running = found_vps.get('status') == 'running' and not found_vps.get('suspended', False)
    if was_running:
        await interaction.followup.send(embed=create_info_embed("Stopping VPS", f"Stopping ZX-NODES VPS `{vps_id}` to apply resource changes..."), ephemeral=True)
        try:
            await execute_lxc(f"lxc stop {vps_id}")
            found_vps['status'] = 'stopped'
            save_data()
        except Exception as e:
            await interaction.followup.send(embed=create_error_embed("Stop Failed", f"Error stopping VPS: {str(e)}"), ephemeral=True)
            return
    
    changes = []
    
    try:
        current_ram_gb = int(found_vps['ram'].replace('GB', ''))
        current_cpu = int(found_vps['cpu'])
        current_disk_gb = int(found_vps['storage'].replace('GB', ''))
        
        new_ram_gb = current_ram_gb
        new_cpu = current_cpu
        new_disk_gb = current_disk_gb
        
        # Add RAM if specified
        if ram is not None and ram > 0:
            new_ram_gb += ram
            ram_mb = new_ram_gb * 1024
            await execute_lxc(f"lxc config set {vps_id} limits.memory {ram_mb}MB")
            changes.append(f"RAM: +{ram}GB (New total: {new_ram_gb}GB)")
        
        # Add CPU if specified
        if cpu is not None and cpu > 0:
            new_cpu += cpu
            await execute_lxc(f"lxc config set {vps_id} limits.cpu {new_cpu}")
            changes.append(f"CPU: +{cpu} cores (New total: {new_cpu} cores)")
        
        # Add disk if specified
        if disk is not None and disk > 0:
            new_disk_gb += disk
            await execute_lxc(f"lxc config device set {vps_id} root size {new_disk_gb}GB")
            changes.append(f"Disk: +{disk}GB (New total: {new_disk_gb}GB)")
        
        # Update VPS data
        found_vps['ram'] = f"{new_ram_gb}GB"
        found_vps['cpu'] = str(new_cpu)
        found_vps['storage'] = f"{new_disk_gb}GB"
        found_vps['config'] = f"{new_ram_gb}GB RAM / {new_cpu} CPU / {new_disk_gb}GB Disk"
        
        # Save changes to database
        vps_data[user_id][vps_index] = found_vps
        save_data()
        
        # Start the VPS if it was running before
        if was_running:
            await execute_lxc(f"lxc start {vps_id}")
            found_vps['status'] = 'running'
            found_vps['last_started_at'] = datetime.now().isoformat()
            save_data()
        
        embed = create_success_embed("Resources Added", f"Successfully added resources to ZX-NODES VPS `{vps_id}`")
        add_field(embed, "Changes Applied", "\n".join(changes), False)
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Resource Addition Failed", f"Error: {str(e)}"))

@bot.tree.command(name='admin-add', description="Add ZX-NODES admin (Main admin only)")
@app_commands.describe(user="The user to promote to admin")
@app_commands.check(is_main_admin_check)
async def admin_add(interaction: discord.Interaction, user: discord.Member):
    """Add ZX-NODES admin (Main admin only)"""
    user_id = str(user.id)
    if user_id == str(MAIN_ADMIN_ID):
        await interaction.response.send_message(embed=create_error_embed("Already Admin", "This user is already the main ZX-NODES admin!"), ephemeral=True)
        return

    if user_id in admin_data.get("admins", []):
        await interaction.response.send_message(embed=create_error_embed("Already Admin", f"{user.mention} is already a ZX-NODES admin!"), ephemeral=True)
        return

    if "admins" not in admin_data:
        admin_data["admins"] = []

    admin_data["admins"].append(user_id)
    save_data()
    await interaction.response.send_message(embed=create_success_embed("Admin Added", f"{user.mention} is now a ZX-NODES admin!"))
    try:
        await user.send(embed=create_embed("🎉 ZX-NODES Admin Role Granted", f"You are now a ZX-NODES admin by {interaction.user.mention}", 0x00ff88))
    except discord.Forbidden:
        await interaction.followup.send(embed=create_info_embed("Notification Failed", f"Could not DM {user.mention}"), ephemeral=True)

@bot.tree.command(name='admin-remove', description="Remove ZX-NODES admin (Main admin only)")
@app_commands.describe(user="The user to demote")
@app_commands.check(is_main_admin_check)
async def admin_remove(interaction: discord.Interaction, user: discord.Member):
    """Remove ZX-NODES admin (Main admin only)"""
    user_id = str(user.id)
    
    # === FIX: Ensure the 'admins' list exists before trying to access it ===
    if "admins" not in admin_data:
        admin_data["admins"] = []
    # === END OF FIX ===
    
    if user_id == str(MAIN_ADMIN_ID):
        await interaction.response.send_message(embed=create_error_embed("Cannot Remove", "You cannot remove the main ZX-NODES admin!"), ephemeral=True)
        return

    if user_id not in admin_data.get("admins", []):
        await interaction.response.send_message(embed=create_error_embed("Not Admin", f"{user.mention} is not a ZX-NODES admin!"), ephemeral=True)
        return

    admin_data["admins"].remove(user_id)
    save_data()
    await interaction.response.send_message(embed=create_success_embed("Admin Removed", f"{user.mention} is no longer a ZX-NODES admin!"))
    try:
        await user.send(embed=create_embed("⚠️ ZX-NODES Admin Role Revoked", f"Your admin role was removed by {interaction.user.mention}", 0xff3366))
    except discord.Forbidden:
        await interaction.followup.send(embed=create_info_embed("Notification Failed", f"Could not DM {user.mention}"), ephemeral=True)

@bot.tree.command(name='admin-list', description="List all ZX-NODES admins (Main admin only)")
@app_commands.check(is_main_admin_check)
async def admin_list(interaction: discord.Interaction):
    """List all ZX-NODES admins (Main admin only)"""
    admins = admin_data.get("admins", [])
    main_admin = await bot.fetch_user(MAIN_ADMIN_ID)

    embed = create_embed("👑 ZX-NODES Admin Team", "Current ZX-NODES administrators:", 0x1a1a1a)
    add_field(embed, "🔰 Main Admin", f"{main_admin.mention} (ID: {MAIN_ADMIN_ID})", False)

    if admins:
        admin_list = []
        for admin_id in admins:
            try:
                admin_user = await bot.fetch_user(int(admin_id))
                admin_list.append(f"• {admin_user.mention} (ID: {admin_id})")
            except:
                admin_list.append(f"• Unknown User (ID: {admin_id})")

        admin_text = "\n".join(admin_list)
        add_field(embed, "🛡️ Admins", admin_text, False)
    else:
        add_field(embed, "🛡️ Admins", "No additional ZX-NODES admins", False)

    await interaction.response.send_message(embed=embed)

@bot.tree.command(name='set-status', description="Set the bot's status (Main Admin only)")
@app_commands.describe(
    activity_type="The type of activity",
    activity_name="The name of the activity"
)
@app_commands.choices(activity_type=[
    app_commands.Choice(name="Watching", value="watching"),
    app_commands.Choice(name="Playing", value="playing"),
    app_commands.Choice(name="Listening to", value="listening"),
    app_commands.Choice(name="Competing in", value="competing")
])
@app_commands.check(is_main_admin_check)
async def set_status(interaction: discord.Interaction, activity_type: str, activity_name: str):
    status_data = {"type": activity_type, "name": activity_name}
    
    # Save the new status
    admin_data["status"] = status_data
    save_data()
    
    # Set the new status immediately
    await set_bot_status(status_data)
    
    await interaction.response.send_message(embed=create_success_embed(
        "Status Updated",
        f"Bot status has been set to: `{activity_type.capitalize()} {activity_name}`. This will persist on restart."
    ), ephemeral=True)

@bot.tree.command(name='userinfo', description="Get detailed information about a ZX-NODES user (Admin only)")
@app_commands.describe(user="The user to get info about")
@app_commands.check(is_admin_check)
async def user_info(interaction: discord.Interaction, user: discord.Member):
    """Get detailed information about a ZX-NODES user (Admin only)"""
    user_id = str(user.id)
    
    await interaction.response.defer()

    # Get user's VPS
    vps_list = vps_data.get(user_id, [])

    embed = create_embed(f"ZX-NODES User Information - {user.name}", f"Detailed information for {user.mention}", 0x1a1a1a)

    # User details
    join_date = user.joined_at.strftime('%Y-%m-%d %H:%M:%S') if user.joined_at else "Unknown"
    add_field(embed, "👤 User Details", f"**Name:** {user.name}\n**ID:** {user.id}\n**Joined:** {join_date}", False)
    
    # === PORT FORWARDING INFO (CHECKING HOST_IP) ===
    if HOST_IP:
        max_ports = port_data.get("users", {}).get(user_id, {}).get("max_ports", 0)
        current_ports = len([f for f in port_data["forwards"] if f["owner_id"] == user_id])
        add_field(embed, "🔌 Port Slots", f"**{current_ports} / {max_ports}** used", False)
    # ===============================================

    # VPS info
    if vps_list:
        vps_info = []
        total_ram = 0
        total_cpu = 0
        total_storage = 0
        running_count = 0
        suspended_count = 0

        for i, vps in enumerate(vps_list):
            status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
            status_text = vps.get('status', 'unknown').upper()
            if vps.get('suspended', False):
                status_text += " (SUSPENDED)"
                suspended_count += 1
            else:
                running_count += 1 if vps.get('status') == 'running' else 0
            vps_info.append(f"{status_emoji} VPS {i+1}: `{vps['container_name']}` - {status_text}")

            # Calculate totals
            ram_gb = int(vps['ram'].replace('GB', ''))
            storage_gb = int(vps['storage'].replace('GB', ''))
            total_ram += ram_gb
            total_cpu += int(vps['cpu'])
            total_storage += storage_gb

        vps_summary = f"**Total VPS:** {len(vps_list)}\n**Running:** {running_count}\n**Suspended:** {suspended_count}\n**Total RAM:** {total_ram}GB\n**Total CPU:** {total_cpu} cores\n**Total Storage:** {total_storage}GB"
        add_field(embed, "🖥️ ZX-NODES VPS Information", vps_summary, False)
        
        # Check if user is admin
        is_admin_user = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
        add_field(embed, "🛡️ ZX-NODES Admin Status", f"**{'Yes' if is_admin_user else 'No'}**", False)

        # Create additional embeds if VPS list is too long
        if len(vps_info) > 10:
            # First embed with first 10 VPS
            first_embed = embed
            add_field(first_embed, "📋 VPS List (1-10)", "\n".join(vps_info[:10]), False)
            await interaction.followup.send(embed=first_embed)
            
            # Additional embeds for remaining VPS
            for i in range(10, len(vps_info), 10):
                chunk = vps_info[i:i+10]
                additional_embed = create_embed(f"ZX-NODES VPS List ({i+1}-{min(i+10, len(vps_info))})", f"More VPS for {user.mention}", 0x1a1a1a)
                add_field(additional_embed, "📋 VPS List", "\n".join(chunk), False)
                await interaction.followup.send(embed=additional_embed)
        else:
            add_field(embed, "📋 VPS List", "\n".join(vps_info), False)
            await interaction.followup.send(embed=embed)
    else:
        add_field(embed, "🖥️ ZX-NODES VPS Information", "**No VPS owned**", False)
        # Check if user is admin
        is_admin_user = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
        add_field(embed, "🛡️ ZX-NODES Admin Status", f"**{'Yes' if is_admin_user else 'No'}**", False)
        await interaction.followup.send(embed=embed)


@bot.tree.command(name='serverstats', description="Show ZX-NODES server statistics (Admin only)")
@app_commands.check(is_admin_check)
async def server_stats(interaction: discord.Interaction):
    """Show ZX-NODES server statistics (Admin only)"""
    total_users = len(vps_data)
    total_vps = sum(len(vps_list) for vps_list in vps_data.values())

    # Calculate resources
    total_ram = 0
    total_cpu = 0
    total_storage = 0
    running_vps = 0
    suspended_vps = 0

    for vps_list in vps_data.values():
        for vps in vps_list:
            ram_gb = int(vps['ram'].replace('GB', ''))
            storage_gb = int(vps['storage'].replace('GB', ''))
            total_ram += ram_gb
            total_cpu += int(vps['cpu'])
            total_storage += storage_gb
            if vps.get('status') == 'running':
                if vps.get('suspended', False):
                    suspended_vps += 1
                else:
                    running_vps += 1
    
    embed = create_embed("📊 ZX-NODES Server Statistics", "Current ZX-NODES server overview", 0x1a1a1a)
    add_field(embed, "👥 Users", f"**Total Users:** {total_users}\n**Total Admins:** {len(admin_data.get('admins', [])) + 1}", False)
    add_field(embed, "🖥️ VPS", f"**Total VPS:** {total_vps}\n**Running:** {running_vps}\n**Suspended:** {suspended_vps}\n**Stopped:** {total_vps - running_vps - suspended_vps}", False)
    add_field(embed, "📈 Resources", f"**Total RAM:** {total_ram}GB\n**Total CPU:** {total_cpu} cores\n**Total Storage:** {total_storage}GB", False)
    
    # === PORT FORWARDING STATS (CHECKING HOST_IP) ===
    if HOST_IP:
        total_ports_allocated = sum(u.get("max_ports", 0) for u in port_data.get("users", {}).values())
        total_ports_used = len(port_data.get("forwards", []))
        add_field(embed, "🔌 Port Forwards", f"**Ports Used:** {total_ports_used}\n**Total Slots Allocated:** {total_ports_allocated}", False)
    # ===============================================

    await interaction.response.send_message(embed=embed)

@bot.tree.command(name='vps-uptime', description="Show uptime for running VPS (Admin only)")
@app_commands.describe(user="Optional: The user to check VPS uptime for.")
@app_commands.check(is_admin_check)
async def vps_uptime(interaction: discord.Interaction, user: Optional[discord.Member] = None):
    """Show uptime for all running VPS (Admin only)"""
    await interaction.response.defer(ephemeral=True)
    
    uptime_info = []
    running_count = 0
    
    target_users = {}
    title = "VPS Uptime Status"
    description = ""

    if user:
        # Check for a specific user
        user_id_to_check = str(user.id)
        if user_id_to_check in vps_data:
            target_users[user_id_to_check] = vps_data[user_id_to_check]
        title = f"VPS Uptime for {user.name}"
    else:
        # Check for all users
        target_users = vps_data

    for user_id, vps_list in target_users.items():
        for vps in vps_list:
            if vps.get('status') == 'running' and not vps.get('suspended', False):
                running_count += 1
                uptime_str = "Unknown"
                if 'last_started_at' in vps:
                    try:
                        start_time = datetime.fromisoformat(vps['last_started_at']) # type: ignore
                        uptime_delta = datetime.now() - start_time # type: ignore
                        days, remainder = divmod(uptime_delta.total_seconds(), 86400)
                        hours, remainder = divmod(remainder, 3600)
                        minutes, _ = divmod(remainder, 60)
                        uptime_str = f"{int(days)}d {int(hours)}h {int(minutes)}m"
                    except (ValueError, TypeError):
                        uptime_str = "Error parsing time"
                uptime_info.append(f"• `{vps['container_name']}`: **{uptime_str}**")

    description = f"Showing uptime for **{running_count}** running VPS."
    embed = create_embed(title, description)
    
    if uptime_info:
        add_field(embed, "Uptime List", "\n".join(uptime_info), False)
    else:
        add_field(embed, "Uptime List", "No running VPS found for the specified scope.", False)
        
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name='vps-top', description="Show top 5 VPS by resource usage (Admin only)")
@app_commands.describe(metric="The metric to sort by: CPU or RAM")
@app_commands.choices(metric=[
    app_commands.Choice(name="CPU", value="cpu"),
    app_commands.Choice(name="RAM", value="ram")
])
@app_commands.check(is_admin_check)
async def vps_top(interaction: discord.Interaction, metric: str):
    """Shows the top 5 most resource-intensive VPS."""
    await interaction.response.defer(ephemeral=True)

    stats = []
    
    # Create a list of tasks to run concurrently
    tasks = []
    vps_map = {}

    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            if vps.get('status') == 'running' and not vps.get('suspended', False):
                container_name = vps['container_name']
                tasks.append(get_container_cpu_pct(container_name))
                tasks.append(get_container_ram_pct(container_name))
                vps_map[container_name] = {'owner_id': user_id}

    if not tasks:
        await interaction.followup.send(embed=create_info_embed("No Running VPS", "There are no running VPS to gather statistics from."), ephemeral=True)
        return

    results = await asyncio.gather(*tasks)

    # Process results
    i = 0
    for container_name in vps_map:
        vps_map[container_name]['cpu'] = results[i]
        vps_map[container_name]['ram'] = results[i+1]
        i += 2

    # Sort the collected stats
    sorted_stats = sorted(vps_map.items(), key=lambda item: item[1][metric], reverse=True)
    top_5 = sorted_stats[:5]

    embed = create_embed(f"🏆 Top 5 VPS by {metric.upper()} Usage", "Displaying the most resource-intensive VPS instances.")
    
    if not top_5:
        add_field(embed, "No Data", "Could not retrieve statistics for any running VPS.", False)
    else:
        description_lines = []
        for i, (name, data) in enumerate(top_5):
            description_lines.append(f"**{i+1}. `{name}`** - CPU: `{data['cpu']:.1f}%` | RAM: `{data['ram']:.1f}%`")
        add_field(embed, "Leaderboard", "\n".join(description_lines), False)

    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name='vpsinfo', description="Get detailed ZX-NODES VPS information (Admin only)")
@app_commands.describe(container_name="The container name (e.g., zx-nodes-123-1). Leave blank to list all.")
@app_commands.check(is_admin_check)
async def vps_info(interaction: discord.Interaction, container_name: Optional[str] = None):
    """Get detailed ZX-NODES VPS information (Admin only)"""
    await interaction.response.defer()
    
    if not container_name:
        # Show all VPS
        all_vps = []
        for user_id, vps_list in vps_data.items():
            try:
                user = await bot.fetch_user(int(user_id))
                for i, vps in enumerate(vps_list):
                    status_text = vps.get('status', 'unknown').upper()
                    if vps.get('suspended', False):
                        status_text += " (SUSPENDED)"
                    all_vps.append(f"**{user.name}** - ZX-NODES VPS {i+1}: `{vps['container_name']}` - {status_text}")
            except:
                pass

        if not all_vps:
            await interaction.followup.send(embed=create_info_embed("No VPS Found", "There are no VPS in the system."))
            return

        # Create multiple embeds if needed to avoid character limit
        embeds_to_send = []
        for i in range(0, len(all_vps), 20):
            chunk = all_vps[i:i+20]
            embed = create_embed(f"🖥️ All ZX-NODES VPS ({i+1}-{min(i+20, len(all_vps))})", f"List of all ZX-NODES VPS deployments", 0x1a1a1a)
            add_field(embed, "VPS List", "\n".join(chunk), False)
            embeds_to_send.append(embed)
            
        await interaction.followup.send(embed=embeds_to_send[0])
        for embed in embeds_to_send[1:]:
            await interaction.followup.send(embed=embed)
            
    else:
        # Show specific VPS info
        found_vps = None
        found_user = None

        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    found_user = await bot.fetch_user(int(user_id))
                    break
            if found_vps:
                break

        if not found_vps:
            await interaction.followup.send(embed=create_error_embed("VPS Not Found", f"No ZX-NODES VPS found with container name: `{container_name}`"))
            return

        suspended_text = " (SUSPENDED)" if found_vps.get('suspended', False) else ""
        embed = create_embed(f"🖥️ ZX-NODES VPS Information - {container_name}", f"Details for VPS owned by {found_user.mention}{suspended_text}", 0x1a1a1a)
        add_field(embed, "👤 Owner", f"**Name:** {found_user.name}\n**ID:** {found_user.id}", False)
        add_field(embed, "📊 Specifications", f"**RAM:** {found_vps['ram']}\n**CPU:** {found_vps['cpu']} Cores\n**Storage:** {found_vps['storage']}", False)
        add_field(embed, "📈 Status", f"**Current:** {found_vps.get('status', 'unknown').upper()}{suspended_text}\n**Suspended:** {found_vps.get('suspended', False)}\n**Created:** {found_vps.get('created_at', 'Unknown')}", False)

        if 'config' in found_vps:
            add_field(embed, "⚙️ Configuration", f"**Config:** {found_vps['config']}", False)

        if found_vps.get('shared_with'):
            shared_users = []
            for shared_id in found_vps['shared_with']:
                try:
                    shared_user = await bot.fetch_user(int(shared_id))
                    shared_users.append(f"• {shared_user.mention}")
                except:
                    shared_users.append(f"• Unknown User ({shared_id})")
            shared_text = "\n".join(shared_users)
            add_field(embed, "🔗 Shared With", shared_text, False)
            
        # === PORT FORWARDING INFO (CHECKING HOST_IP) ===
        if HOST_IP:
            container_ports = [f for f in port_data["forwards"] if f["container_name"] == container_name]
            if container_ports:
                port_text = []
                for f in container_ports:
                    # SỬA Ở ĐÂY: Hiển thị cả hai port
                    port_text.append(f"• **ID:** {f['id']} | `{f['host_port']} -> {f['internal_port']}` ({f['protocol'].upper()})")
                add_field(embed, "🔌 Port Forwards", "\n".join(port_text), False)
        # ===============================================

        await interaction.followup.send(embed=embed)

@bot.tree.command(name='restart-vps', description="Restart a ZX-NODES VPS (Admin only)")
@app_commands.describe(container_name="The container name (e.g., zx-nodes-123-1)")
@app_commands.check(is_admin_check)
async def restart_vps(interaction: discord.Interaction, container_name: str):
    """Restart a ZX-NODES VPS (Admin only)"""
    await interaction.response.send_message(embed=create_info_embed("Restarting VPS", f"Restarting ZX-NODES VPS `{container_name}`..."))

    try:
        await execute_lxc(f"lxc restart {container_name}")

        # Update status in database
        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    vps['last_started_at'] = datetime.now().isoformat()
                    save_data()
                    break

        await interaction.followup.send(embed=create_success_embed("VPS Restarted", f"ZX-NODES VPS `{container_name}` has been restarted successfully!"))

    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Restart Failed", f"Error: {str(e)}"))

@bot.tree.command(name='backup-vps', description="Create a snapshot of a ZX-NODES VPS (Admin only)")
@app_commands.describe(container_name="The container name (e.g., zx-nodes-123-1)")
@app_commands.check(is_admin_check)
async def backup_vps(interaction: discord.Interaction, container_name: str):
    """Create a snapshot of a ZX-NODES VPS (Admin only)"""
    snapshot_name = f"unixnodes-{container_name}-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    await interaction.response.send_message(embed=create_info_embed("Creating ZX-NODES Backup", f"Creating snapshot of `{container_name}`..."))

    try:
        await execute_lxc(f"lxc snapshot {container_name} {snapshot_name}")
        await interaction.followup.send(embed=create_success_embed("Backup Created", f"ZX-NODES Snapshot `{snapshot_name}` created successfully!"))

    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Backup Failed", f"Error: {str(e)}"))

@bot.tree.command(name='restore-vps', description="Restore a ZX-NODES VPS from snapshot (Admin only)")
@app_commands.describe(container_name="The container to restore", snapshot_name="The snapshot name to restore from")
@app_commands.check(is_admin_check)
async def restore_vps(interaction: discord.Interaction, container_name: str, snapshot_name: str):
    """Restore a ZX-NODES VPS from snapshot (Admin only)"""
    await interaction.response.send_message(embed=create_info_embed("Restoring VPS", f"Restoring `{container_name}` from ZX-NODES snapshot `{snapshot_name}`..."))

    try:
        await execute_lxc(f"lxc restore {container_name} {snapshot_name}")
        await interaction.followup.send(embed=create_success_embed("VPS Restored", f"ZX-NODES VPS `{container_name}` has been restored from snapshot!"))

    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Restore Failed", f"Error: {str(e)}"))

@bot.tree.command(name='list-snapshots', description="List all snapshots for a ZX-NODES VPS (Admin only)")
@app_commands.describe(container_name="The container name (e.g., zx-nodes-123-1)")
@app_commands.check(is_admin_check)
async def list_snapshots(interaction: discord.Interaction, container_name: str):
    """List all snapshots for a ZX-NODES VPS (Admin only)"""
    await interaction.response.defer()
    try:
        # Improved parsing for lxc list --type snapshot
        proc = await asyncio.create_subprocess_exec(
            "lxc", "list", "--type", "snapshot", "--columns", "n",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise Exception(stderr.decode())

        snapshots = [line.strip() for line in stdout.decode().splitlines() if line.strip() and container_name in line]
        snapshots = [snap.split()[0] for snap in snapshots if snap]  # Extract names

        if snapshots:
            # Create multiple embeds if needed to avoid character limit
            embeds_to_send = []
            for i in range(0, len(snapshots), 20):
                chunk = snapshots[i:i+20]
                embed = create_embed(f"📸 ZX-NODES Snapshots for {container_name} ({i+1}-{min(i+20, len(snapshots))})", f"List of snapshots", 0x1a1a1a)
                add_field(embed, "Snapshots", "\n".join([f"• {snap}" for snap in chunk]), False)
                embeds_to_send.append(embed)
            
            await interaction.followup.send(embed=embeds_to_send[0])
            for embed in embeds_to_send[1:]:
                await interaction.followup.send(embed=embed)
        else:
            await interaction.followup.send(embed=create_info_embed("No Snapshots", f"No ZX-NODES snapshots found for `{container_name}`"))

    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Error", f"Error listing snapshots: {str(e)}"))

@bot.tree.command(name='exec', description="Execute a command inside a ZX-NODES VPS (Admin only)")
@app_commands.describe(container_name="The container name", command="The command to execute")
@app_commands.check(is_admin_check)
async def execute_command(interaction: discord.Interaction, container_name: str, command: str):
    """Execute a command inside a ZX-NODES VPS (Admin only)"""
    await interaction.response.send_message(embed=create_info_embed("Executing Command", f"Running command in ZX-NODES VPS `{container_name}`..."))

    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "bash", "-c", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        output = stdout.decode() if stdout else "No output"
        error = stderr.decode() if stderr else ""

        embed = create_embed(f"Command Output - {container_name}", f"Command: `{command}`", 0x1a1a1a)

        if output.strip():
            # Split output if too long
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"
            add_field(embed, "📤 Output", f"```\n{output}\n```", False)

        if error.strip():
            if len(error) > 1000:
                error = error[:1000] + "\n... (truncated)"
            add_field(embed, "⚠️ Error", f"```\n{error}\n```", False)

        add_field(embed, "🔄 Exit Code", f"**{proc.returncode}**", False)

        await interaction.followup.send(embed=embed)

    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Execution Failed", f"Error: {str(e)}"))

@bot.tree.command(name='stop-vps-all', description="Stop all ZX-NODES VPS using lxc stop --all --force (Admin only)")
@app_commands.check(is_admin_check)
async def stop_all_vps(interaction: discord.Interaction):
    """Stop all ZX-NODES VPS using lxc stop --all --force (Admin only)"""
    
    class ConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)

        @discord.ui.button(label="Stop All VPS", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.defer()

            try:
                # Execute the lxc stop --all --force command
                proc = await asyncio.create_subprocess_exec(
                    "lxc", "stop", "--all", "--force",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode == 0:
                    # Update all VPS status in database to stopped
                    stopped_count = 0
                    for user_id, vps_list in vps_data.items():
                        for vps in vps_list:
                            if vps.get('status') == 'running':
                                vps['status'] = 'stopped'
                                vps['suspended'] = False
                                stopped_count += 1

                    save_data()
                    
                    # === PORT FORWARDING NOTE ===
                    # Port forward (proxy) devices stop automatically when the container stops.
                    # They will restart when the container restarts. No DB change needed.

                    embed = create_success_embed("All ZX-NODES VPS Stopped", f"Successfully stopped {stopped_count} VPS using `lxc stop --all --force`")
                    output_text = stdout.decode() if stdout else 'No output'
                    add_field(embed, "Command Output", f"```\n{output_text}\n```", False)
                    await interaction.followup.send(embed=embed)
                else:
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    embed = create_error_embed("Stop Failed", f"Failed to stop ZX-NODES VPS: {error_msg}")
                    await interaction.followup.send(embed=embed)

            except Exception as e:
                embed = create_error_embed("Error", f"Error stopping VPS: {str(e)}")
                await interaction.followup.send(embed=embed)

        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.edit_message(embed=create_info_embed("Operation Cancelled", "The stop all ZX-NODES VPS operation has been cancelled."), view=None)

    await interaction.response.send_message(
        embed=create_warning_embed("Stopping All ZX-NODES VPS", "⚠️ **WARNING:** This will stop ALL running VPS on the ZX-NODES server.\n\nThis action cannot be undone. Continue?"),
        view=ConfirmView()
    )


@bot.tree.command(name='cpu-monitor', description="Control ZX-NODES CPU monitoring system (Admin only)")
@app_commands.describe(action="The action to perform: status, enable, or disable")
@app_commands.choices(action=[
    app_commands.Choice(name="status", value="status"),
    app_commands.Choice(name="enable", value="enable"),
    app_commands.Choice(name="disable", value="disable"),
])
@app_commands.check(is_admin_check)
async def cpu_monitor_control(interaction: discord.Interaction, action: str = "status"):
    """Control ZX-NODES CPU monitoring system (Admin only)"""
    global cpu_monitor_active
    
    if action.lower() == "status":
        status = "Active" if cpu_monitor_active else "Inactive"
        embed = create_embed("ZX-NODES CPU Monitor Status", f"ZX-NODES CPU monitoring is currently **{status}**", 0x00ccff if cpu_monitor_active else 0xffaa00)
        add_field(embed, "Threshold", f"{CPU_THRESHOLD}% CPU usage", True)
        add_field(embed, "Check Interval", f"60 seconds (host)", True)
        await interaction.response.send_message(embed=embed)
    elif action.lower() == "enable":
        cpu_monitor_active = True
        await interaction.response.send_message(embed=create_success_embed("CPU Monitor Enabled", "ZX-NODES CPU monitoring has been enabled."))
    elif action.lower() == "disable":
        cpu_monitor_active = False
        await interaction.response.send_message(embed=create_warning_embed("CPU Monitor Disabled", "ZX-NODES CPU monitoring has been disabled."))
    else:
        await interaction.response.send_message(embed=create_error_embed("Invalid Action", "Use: `/cpu-monitor <status|enable|disable>`"), ephemeral=True)

@bot.tree.command(name='resize-vps', description="Resize ZX-NODES VPS resources (Admin only)")
@app_commands.describe(
    container_name="The container name (e.g., zx-nodes-123-1)",
    ram="New RAM in GB",
    cpu="New number of CPU cores",
    disk="New disk size in GB"
)
@app_commands.check(is_admin_check)
async def resize_vps(interaction: discord.Interaction, container_name: str, ram: Optional[int] = None, cpu: Optional[int] = None, disk: Optional[int] = None):
    """Resize ZX-NODES VPS resources (Admin only)"""
    if ram is None and cpu is None and disk is None:
        await interaction.response.send_message(embed=create_error_embed("Missing Parameters", "Please specify at least one resource to resize (ram, cpu, or disk)"), ephemeral=True)
        return
    
    # Find the VPS in our database
    found_vps = None
    user_id = None
    vps_index = None
    
    for uid, vps_list in vps_data.items():
        for i, vps in enumerate(vps_list):
            if vps['container_name'] == container_name:
                found_vps = vps
                user_id = uid
                vps_index = i
                break
        if found_vps:
            break
    
    if not found_vps:
        await interaction.response.send_message(embed=create_error_embed("VPS Not Found", f"No ZX-NODES VPS found with container name: `{container_name}`"), ephemeral=True)
        return
    
    await interaction.response.defer()
    
    was_running = found_vps.get('status') == 'running' and not found_vps.get('suspended', False)
    if was_running:
        await interaction.followup.send(embed=create_info_embed("Stopping VPS", f"Stopping ZX-NODES VPS `{container_name}` to apply resource changes..."), ephemeral=True)
        try:
            await execute_lxc(f"lxc stop {container_name}")
            found_vps['status'] = 'stopped'
            save_data()
        except Exception as e:
            await interaction.followup.send(embed=create_error_embed("Stop Failed", f"Error stopping VPS: {str(e)}"), ephemeral=True)
            return
    
    changes = []
    
    try:
        new_ram = int(found_vps['ram'].replace('GB', ''))
        new_cpu = int(found_vps['cpu'])
        new_disk = int(found_vps['storage'].replace('GB', ''))
        
        # Resize RAM if specified
        if ram is not None and ram > 0:
            new_ram = ram
            ram_mb = ram * 1024
            await execute_lxc(f"lxc config set {container_name} limits.memory {ram_mb}MB")
            changes.append(f"RAM: {ram}GB")
        
        # Resize CPU if specified
        if cpu is not None and cpu > 0:
            new_cpu = cpu
            await execute_lxc(f"lxc config set {container_name} limits.cpu {cpu}")
            changes.append(f"CPU: {cpu} cores")
        
        # Resize disk if specified
        if disk is not None and disk > 0:
            new_disk = disk
            await execute_lxc(f"lxc config device set {container_name} root size {disk}GB")
            changes.append(f"Disk: {disk}GB")
        
        # Update VPS data
        found_vps['ram'] = f"{new_ram}GB"
        found_vps['cpu'] = str(new_cpu)
        found_vps['storage'] = f"{new_disk}GB"
        found_vps['config'] = f"{new_ram}GB RAM / {new_cpu} CPU / {new_disk}GB Disk"
        
        # Save changes to database
        vps_data[user_id][vps_index] = found_vps
        save_data()
        
        # Start the VPS if it was running before
        if was_running:
            await execute_lxc(f"lxc start {container_name}")
            found_vps['status'] = 'running'
            found_vps['last_started_at'] = datetime.now().isoformat()
            save_data()
        
        embed = create_success_embed("VPS Resized", f"Successfully resized resources for ZX-NODES VPS `{container_name}`")
        add_field(embed, "Changes Applied", "\n".join(changes), False)
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Resize Failed", f"Error: {str(e)}"))

@bot.tree.command(name='delete-vps-some', description="Select and delete multiple VPS for a user (Admin only)")
@app_commands.describe(user="The user whose VPS to delete")
@app_commands.check(is_admin_check)
async def delete_vps_some(interaction: discord.Interaction, user: discord.Member):
    """Select and delete multiple VPS for a user."""
    user_id = str(user.id)
    vps_list = vps_data.get(user_id)

    if not vps_list:
        return await interaction.response.send_message(embed=create_error_embed("No VPS Found", f"{user.mention} does not own any VPS."), ephemeral=True)

    embed = create_info_embed(
        f"Delete VPS for {user.name}",
        "Select the VPS you want to permanently delete from the dropdown menu below. You can select multiple."
    )
    
    view = DeleteVpsSomeView(user, vps_list, interaction)
    
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


@bot.tree.command(name='clone-vps', description="Clone a VPS and assign it to a new user (Admin only)")
@app_commands.describe(
    container_name="The container to clone",
    user="The new user who will own the clone",
    new_name="Optional: A specific name for the new container"
)
@app_commands.check(is_admin_check)
async def clone_vps(interaction: discord.Interaction, container_name: str, user: discord.Member, new_name: Optional[str] = None):
    """Clone a VPS and assign it to a new user (Admin only)"""
    await interaction.response.defer() # Use defer, cloning takes time

    # 1. Find the original VPS
    found_vps = None
    original_owner_id = None
    
    for uid, vps_list in vps_data.items():
        for vps in vps_list:
            if vps['container_name'] == container_name:
                found_vps = vps.copy() # IMPORTANT: Use .copy()
                original_owner_id = uid
                break
        if found_vps:
            break
    
    if not found_vps:
        await interaction.followup.send(embed=create_error_embed("VPS Not Found", f"No ZX-NODES VPS found with container name: `{container_name}`"))
        return

    # 2. Determine New Owner and New Name
    new_owner_id = str(user.id)
    
    if new_owner_id not in vps_data:
        vps_data[new_owner_id] = []
        
    vps_count = len(vps_data[new_owner_id]) + 1
    
    # If new_name wasn't provided, generate one based on the NEW user
    if not new_name:
        new_name = f"zx-nodes-{new_owner_id}-{vps_count}"
    
    await interaction.followup.send(embed=create_info_embed("Cloning VPS", f"Cloning `{container_name}` (from user <@{original_owner_id}>) to `{new_name}` (for {user.mention})..."))

    # 3. Execute Clone and Update Database
    try:
        # Clone the container
        await execute_lxc(f"lxc copy {container_name} {new_name}")
        
        # Start the new container
        await execute_lxc(f"lxc start {new_name}")
        
        # Create a new VPS entry in the database
        # 'found_vps' is already a .copy() from Step 1
        new_vps = found_vps 
        new_vps['container_name'] = new_name
        new_vps['status'] = 'running'
        new_vps['suspended'] = False
        new_vps['suspension_history'] = []
        new_vps['created_at'] = datetime.now().isoformat()
        new_vps['last_started_at'] = datetime.now().isoformat()
        new_vps['shared_with'] = [] # Clones are not shared by default
        
        vps_data[new_owner_id].append(new_vps) # Append to the NEW owner
        save_data()
        
        # Assign role to the NEW owner
        if interaction.guild:
            vps_role = await get_or_create_vps_role(interaction.guild)
            if vps_role:
                try:
                    await user.add_roles(vps_role, reason="ZX-NODES VPS clone ownership granted")
                except discord.Forbidden:
                    logger.warning(f"Failed to assign ZX-NODES VPS role to new clone owner {user.name}")

        embed = create_success_embed("VPS Cloned Successfully", f"Successfully cloned `{container_name}` to `{new_name}` and assigned to {user.mention}.")
        add_field(embed, "New Owner", user.mention, True)
        add_field(embed, "New Container", f"`{new_name}`", True)
        add_field(embed, "New VPS ID", f"#{vps_count}", True)
        add_field(embed, "Resources", f"**RAM:** {new_vps['ram']}\n**CPU:** {new_vps['cpu']} Cores\n**Storage:** {new_vps['storage']}", False)
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Clone Failed", f"Error: {str(e)}"))

@bot.tree.command(name='migrate-vps', description="Migrate a ZX-NODES VPS to a different storage pool (Admin only)")
@app_commands.describe(container_name="The container to migrate", target_pool="The name of the target storage pool")
@app_commands.check(is_admin_check)
async def migrate_vps(interaction: discord.Interaction, container_name: str, target_pool: str):
    """Migrate a ZX-NODES VPS to a different storage pool (Admin only)"""
    await interaction.response.send_message(embed=create_info_embed("Migrating VPS", f"Migrating ZX-NODES VPS `{container_name}` to storage pool `{target_pool}`..."))
    
    try:
        # Stop the container first
        await execute_lxc(f"lxc stop {container_name}")
        
        # Create a temporary name for migration
        temp_name = f"unixnodes-{container_name}-temp-{int(time.time())}"
        
        # Copy to new pool with temp name
        await execute_lxc(f"lxc copy {container_name} {temp_name} --storage {target_pool}")
        
        # Delete the old container
        await execute_lxc(f"lxc delete {container_name} --force")
        
        # Rename temp to original name
        await execute_lxc(f"lxc rename {temp_name} {container_name}")
        
        # Start the container again
        await execute_lxc(f"lxc start {container_name}")
        
        # Update status in database
        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    vps['last_started_at'] = datetime.now().isoformat()
                    save_data()
                    break
        
        await interaction.followup.send(embed=create_success_embed("VPS Migrated", f"Successfully migrated ZX-NODES VPS `{container_name}` to storage pool `{target_pool}`"))
        
    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Migration Failed", f"Error: {str(e)}"))

@bot.tree.command(name='vps-stats', description="Show detailed resource usage statistics for a ZX-NODES VPS (Admin only)")
@app_commands.describe(container_name="The container name")
@app_commands.check(is_admin_check)
async def vps_stats(interaction: discord.Interaction, container_name: str):
    """Show detailed resource usage statistics for a ZX-NODES VPS (Admin only)"""
    await interaction.response.send_message(embed=create_info_embed("Gathering Statistics", f"Collecting statistics for ZX-NODES VPS `{container_name}`..."))
    
    try:
        status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)
        network_usage = "N/A"  # Simplified for now
        
        # Create embed with statistics
        embed = create_embed(f"📊 ZX-NODES VPS Statistics - {container_name}", f"Resource usage statistics", 0x1a1a1a)
        add_field(embed, "📈 Status", f"**{status}**", False)
        add_field(embed, "💻 CPU Usage", f"**{cpu_usage}**", True)
        add_field(embed, "🧠 Memory Usage", f"**{memory_usage}**", True)
        add_field(embed, "💾 Disk Usage", f"**{disk_usage}**", True)
        add_field(embed, "🌐 Network Usage", f"**{network_usage}**", False)
        
        # Find the VPS in our database
        found_vps = None
        for vps_list in vps_data.values():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    break
            if found_vps:
                break
        
        if found_vps:
            suspended_text = " (SUSPENDED)" if found_vps.get('suspended', False) else ""
            add_field(embed, "📋 Allocated Resources", 
                           f"**RAM:** {found_vps['ram']}\n**CPU:** {found_vps['cpu']} Cores\n**Storage:** {found_vps['storage']}\n**Status:** {found_vps.get('status', 'unknown').upper()}{suspended_text}", 
                           False)
        
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Statistics Failed", f"Error: {str(e)}"))

@bot.tree.command(name='vps-network', description="Manage ZX-NODES VPS network settings (Admin only)")
@app_commands.describe(container_name="The container name", action="list, add, remove, or limit", value="Value for the action (e.g., bridge, device, or limit)")
@app_commands.choices(action=[
    app_commands.Choice(name="list", value="list"),
    app_commands.Choice(name="add", value="add"),
    app_commands.Choice(name="remove", value="remove"),
    app_commands.Choice(name="limit", value="limit"),
])
@app_commands.check(is_admin_check)
async def vps_network(interaction: discord.Interaction, container_name: str, action: str, value: Optional[str] = None):
    """Manage ZX-NODES VPS network settings (Admin only)"""
    
    await interaction.response.defer()
    
    try:
        action_lower = action.lower()

        if action_lower == "list":
            # List network interfaces
            proc = await asyncio.create_subprocess_exec(
                "lxc", "exec", container_name, "--", "ip", "addr",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                output = stdout.decode()
                # Split output if too long
                if len(output) > 1000:
                    output = output[:1000] + "\n... (truncated)"
                
                embed = create_embed(f"🌐 ZX-NODES Network Interfaces - {container_name}", "Network configuration", 0x1a1a1a)
                add_field(embed, "Interfaces", f"```\n{output}\n```", False)
                await interaction.followup.send(embed=embed)
            else:
                await interaction.followup.send(embed=create_error_embed("Error", f"Failed to list network interfaces: {stderr.decode()}"))
        
        elif action_lower == "limit":
            if not value:
                await interaction.followup.send(embed=create_error_embed("Missing Value", "Please provide a limit (e.g., `100Mbit`)."))
                return
            # Set network limit (assuming eth0 for simplicity)
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.egress {value}")
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.ingress {value}")
            await interaction.followup.send(embed=create_success_embed("Network Limited", f"Set ZX-NODES network limit to {value} for `eth0` on `{container_name}`"))
        
        elif action_lower == "add":
            if not value:
                await interaction.followup.send(embed=create_error_embed("Missing Value", "Please provide the host bridge name to connect to."))
                return
            
            bridge_name = value
            # Find next available eth device
            output = await execute_lxc(f"lxc config device list {container_name}")
            devices = output.splitlines()
            eth_devices = [d for d in devices if d.startswith('eth') and d[3:].isdigit()]
            
            eth_numbers = [0] # Start with 0 (for eth0)
            if eth_devices:
                eth_numbers.extend([int(d[3:]) for d in eth_devices])
            
            new_eth_num = max(eth_numbers) + 1
            new_device_name = f"eth{new_eth_num}"
            
            # Add the new device
            await execute_lxc(f"lxc config device add {container_name} {new_device_name} nic nictype=bridged parent={bridge_name}")
            await interaction.followup.send(embed=create_success_embed("Network Device Added", f"Successfully added device `{new_device_name}` to `{container_name}` on bridge `{bridge_name}`"))

        elif action_lower == "remove":
            if not value:
                await interaction.followup.send(embed=create_error_embed("Missing Value", "Please provide the device name to remove (e.g., `eth1`)."))
                return
            
            device_name = value
            if device_name.lower() == 'eth0':
                await interaction.followup.send(embed=create_error_embed("Action Denied", "Cannot remove the primary `eth0` device."))
                return
            
            await execute_lxc(f"lxc config device remove {container_name} {device_name}")
            await interaction.followup.send(embed=create_success_embed("Network Device Removed", f"Successfully removed device `{device_name}` from `{container_name}`"))
        
        else:
            # This case should not be reachable due to @app_commands.choices
            await interaction.followup.send(embed=create_error_embed("Invalid Action", "Invalid action specified."))
    
    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Network Management Failed", f"Error: {str(e)}"))

@bot.tree.command(name='vps-processes', description="Show running processes in a ZX-NODES VPS (Admin only)")
@app_commands.describe(container_name="The container name")
@app_commands.check(is_admin_check)
async def vps_processes(interaction: discord.Interaction, container_name: str):
    """Show running processes in a ZX-NODES VPS (Admin only)"""
    await interaction.response.send_message(embed=create_info_embed("Gathering Processes", f"Listing processes in ZX-NODES VPS `{container_name}`..."))
    
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "ps", "aux",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            output = stdout.decode()
            # Split output if too long
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"
            
            embed = create_embed(f"⚙️ ZX-NODES Processes - {container_name}", "Running processes", 0x1a1a1a)
            add_field(embed, "Process List", f"```\n{output}\n```", False)
            await interaction.followup.send(embed=embed)
        else:
            await interaction.followup.send(embed=create_error_embed("Error", f"Failed to list processes: {stderr.decode()}"))
    
    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Process Listing Failed", f"Error: {str(e)}"))

@bot.tree.command(name='vps-logs', description="Show recent logs from a ZX-NODES VPS (Admin only)")
@app_commands.describe(container_name="The container name", lines="Number of lines to show (default 50)")
@app_commands.check(is_admin_check)
async def vps_logs(interaction: discord.Interaction, container_name: str, lines: int = 50):
    """Show recent logs from a ZX-NODES VPS (Admin only)"""
    await interaction.response.send_message(embed=create_info_embed("Gathering Logs", f"Fetching last {lines} lines from ZX-NODES VPS `{container_name}`..."))
    
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc", "exec", container_name, "--", "journalctl", "-n", str(lines),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            output = stdout.decode()
            # Split output if too long
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"
            
            embed = create_embed(f"📋 ZX-NODES Logs - {container_name}", f"Last {lines} log lines", 0x1a1a1a)
            add_field(embed, "System Logs", f"```\n{output}\n```", False)
            await interaction.followup.send(embed=embed)
        else:
            await interaction.followup.send(embed=create_error_embed("Error", f"Failed to fetch logs: {stderr.decode()}"))
    
    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Log Retrieval Failed", f"Error: {str(e)}"))

@bot.tree.command(name='suspend-vps', description="Suspend a ZX-NODES VPS (Admin only)")
@app_commands.describe(container_name="The container to suspend", reason="Reason for suspension")
@app_commands.check(is_admin_check)
async def suspend_vps(interaction: discord.Interaction, container_name: str, reason: str = "Admin action"):
    """Suspend a ZX-NODES VPS (Admin only)"""
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if vps.get('status') != 'running':
                    await interaction.response.send_message(embed=create_error_embed("Cannot Suspend", "ZX-NODES VPS must be running to suspend."), ephemeral=True)
                    return
                try:
                    await interaction.response.defer()
                    await execute_lxc(f"lxc stop {container_name}")
                    vps['status'] = 'suspended'
                    vps['suspended'] = True
                    if 'suspension_history' not in vps:
                        vps['suspension_history'] = []
                    vps['suspension_history'].append({
                        'time': datetime.now().isoformat(),
                        'reason': reason,
                        'by': f"{interaction.user.name} ({interaction.user.id})"
                    })
                    save_data()
                except Exception as e:
                    await interaction.followup.send(embed=create_error_embed("Suspend Failed", str(e)), ephemeral=True)
                    return
                # DM owner
                try:
                    owner = await bot.fetch_user(int(uid))
                    embed = create_warning_embed("🚨 ZX-NODES VPS Suspended", f"Your VPS `{container_name}` has been suspended by an admin.\n\n**Reason:** {reason}\n\nContact a ZX-NODES admin to unsuspend.")
                    await owner.send(embed=embed)
                except Exception as dm_e:
                    logger.error(f"Failed to DM owner {uid}: {dm_e}")
                await interaction.followup.send(embed=create_success_embed("VPS Suspended", f"ZX-NODES VPS `{container_name}` suspended. Reason: {reason}"))
                found = True
                break
        if found:
            break
    if not found:
        await interaction.response.send_message(embed=create_error_embed("Not Found", f"ZX-NODES VPS `{container_name}` not found."), ephemeral=True)

@bot.tree.command(name='unsuspend-vps', description="Unsuspend a ZX-NODES VPS (Admin only)")
@app_commands.describe(container_name="The container to unsuspend")
@app_commands.check(is_admin_check)
async def unsuspend_vps(interaction: discord.Interaction, container_name: str):
    """Unsuspend a ZX-NODES VPS (Admin only)"""
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if not vps.get('suspended', False):
                    await interaction.response.send_message(embed=create_error_embed("Not Suspended", "ZX-NODES VPS is not suspended."), ephemeral=True)
                    return
                try:
                    await interaction.response.defer()
                    vps['suspended'] = False
                    vps['status'] = 'running'
                    vps['last_started_at'] = datetime.now().isoformat()
                    await execute_lxc(f"lxc start {container_name}")
                    save_data()
                    await interaction.followup.send(embed=create_success_embed("VPS Unsuspended", f"ZX-NODES VPS `{container_name}` unsuspended and started."))
                    found = True
                except Exception as e:
                    await interaction.followup.send(embed=create_error_embed("Start Failed", str(e)))
                break
        if found:
            break
    if not found:
        await interaction.response.send_message(embed=create_error_embed("Not Found", f"ZX-NODES VPS `{container_name}` not found."), ephemeral=True)

@bot.tree.command(name='suspension-logs', description="View ZX-NODES suspension logs (Admin only)")
@app_commands.describe(container_name="Optional: The container to get logs for")
@app_commands.check(is_admin_check)
async def suspension_logs(interaction: discord.Interaction, container_name: Optional[str] = None):
    """View ZX-NODES suspension logs (Admin only)"""
    await interaction.response.defer()
    
    if container_name:
        # Specific VPS
        found = None
        for lst in vps_data.values():
            for vps in lst:
                if vps['container_name'] == container_name:
                    found = vps
                    break
            if found:
                break
        if not found:
            await interaction.followup.send(embed=create_error_embed("Not Found", f"ZX-NODES VPS `{container_name}` not found."), ephemeral=True)
            return
        history = found.get('suspension_history', [])
        if not history:
            await interaction.followup.send(embed=create_info_embed("No Suspensions", f"No ZX-NODES suspension history for `{container_name}`."), ephemeral=True)
            return
        embed = create_embed("ZX-NODES Suspension History", f"For `{container_name}`")
        text = []
        for h in sorted(history, key=lambda x: x['time'], reverse=True)[:10]:  # Last 10
            t = datetime.fromisoformat(h['time']).strftime('%Y-%m-%d %H:%M:%S')
            text.append(f"**{t}** - {h['reason']} (by {h['by']})")
        add_field(embed, "History", "\n".join(text), False)
        if len(history) > 10:
            add_field(embed, "Note", "Showing last 10 entries.")
        await interaction.followup.send(embed=embed)
    else:
        # All logs
        all_logs = []
        for uid, lst in vps_data.items():
            for vps in lst:
                h = vps.get('suspension_history', [])
                for event in sorted(h, key=lambda x: x['time'], reverse=True):
                    t = datetime.fromisoformat(event['time']).strftime('%Y-%m-%d %H:%M')
                    all_logs.append(f"**{t}** - VPS `{vps['container_name']}` (Owner: <@{uid}>) - {event['reason']} (by {event['by']})")
        if not all_logs:
            await interaction.followup.send(embed=create_info_embed("No Suspensions", "No ZX-NODES suspension events recorded."), ephemeral=True)
            return
        
        # Split into embeds
        embeds_to_send = []
        for i in range(0, len(all_logs), 10):
            chunk = all_logs[i:i+10]
            embed = create_embed(f"ZX-NODES Suspension Logs ({i+1}-{min(i+10, len(all_logs))})", f"Global suspension events (newest first)")
            add_field(embed, "Events", "\n".join(chunk), False)
            embeds_to_send.append(embed)
            
        await interaction.followup.send(embed=embeds_to_send[0])
        for embed in embeds_to_send[1:]:
            await interaction.followup.send(embed=embed)

# === PORT FORWARDING COMMANDS ===

@bot.tree.command(name='ports-add-user', description="Allocate port slots to user (Admin only)")
@app_commands.describe(amount="Number of port slots to add", user="The user to allocate slots to")
@app_commands.check(is_admin_check)
async def ports_add_user(interaction: discord.Interaction, amount: int, user: discord.Member):
    # === IPV4 CHECK ===
    if not HOST_IP:
        await interaction.response.send_message(embed=create_error_embed(
            "IPv4 Not Configured",
            "The host server does not currently have an IPv4 address configured. Please contact an admin."
        ), ephemeral=True)
        return
    # ==================
    
    user_id = str(user.id)
    
    if user_id not in port_data["users"]:
        port_data["users"][user_id] = {"max_ports": 0}
        
    port_data["users"][user_id]["max_ports"] += amount
    save_data()
    
    new_total = port_data["users"][user_id]["max_ports"]
    await interaction.response.send_message(embed=create_success_embed(
        "Port Slots Allocated",
        f"Added {amount} port slots to {user.mention}. They now have a total of {new_total} slots."
    ))

@bot.tree.command(name='ports-remove-user', description="Deallocate port slots from user (Admin only)")
@app_commands.describe(amount="Number of port slots to remove", user="The user to deallocate slots from")
@app_commands.check(is_admin_check)
async def ports_remove_user(interaction: discord.Interaction, amount: int, user: discord.Member):
    # === IPV4 CHECK ===
    if not HOST_IP:
        await interaction.response.send_message(embed=create_error_embed(
            "IPv4 Not Configured",
            "The host server does not currently have an IPv4 address configured. Please contact an admin."
        ), ephemeral=True)
        return
    # ==================

    user_id = str(user.id)
    
    if user_id not in port_data["users"]:
        port_data["users"][user_id] = {"max_ports": 0}
    
    current_total = port_data["users"][user_id]["max_ports"]
    port_data["users"][user_id]["max_ports"] = max(0, current_total - amount)
    save_data()
    
    new_total = port_data["users"][user_id]["max_ports"]
    await interaction.response.send_message(embed=create_success_embed(
        "Port Slots Deallocated",
        f"Removed {amount} port slots from {user.mention}. They now have a total of {new_total} slots."
    ))

# === COMMAND UPDATED ===
@bot.tree.command(name='ports-add', description="Forward a random host port to your VPS's internal port")
@app_commands.describe(
    vps_number="Your VPS number (from /myvps)", 
    internal_port="The internal container port (e.g., 22, 80, 25565)", 
    protocol="The protocol (default: tcp)"
)
@app_commands.choices(protocol=[
    app_commands.Choice(name="TCP", value="tcp"),
    app_commands.Choice(name="UDP", value="udp")
])
async def ports_add(interaction: discord.Interaction, vps_number: int, internal_port: int, protocol: str = "tcp"):
    # === IPV4 CHECK ===
    if not HOST_IP:
        await interaction.response.send_message(embed=create_error_embed(
            "IPv4 Not Configured",
            "The host server does not currently have an IPv4 address configured. Please contact an admin."
        ), ephemeral=True)
        return
    # ==================

    await interaction.response.defer()
    user_id = str(interaction.user.id)
    
    # 1. Check user's port slots
    max_ports = port_data.get("users", {}).get(user_id, {}).get("max_ports", 0)
    current_ports = len([f for f in port_data["forwards"] if f["owner_id"] == user_id])
    
    if current_ports >= max_ports:
        await interaction.followup.send(embed=create_error_embed(
            "No Port Slots",
            f"You are already using {current_ports}/{max_ports} port slots. Contact an admin to get more."
        ), ephemeral=True)
        return
        
    # 2. Check if user owns the VPS
    vps_list = vps_data.get(user_id, [])
    if not vps_list or vps_number < 1 or vps_number > len(vps_list):
        await interaction.followup.send(embed=create_error_embed("Invalid VPS", "You do not own this VPS or the number is invalid. Use `/myvps` to check."), ephemeral=True)
        return
        
    vps = vps_list[vps_number - 1]
    container_name = vps["container_name"]
    
    # 3. Find a free random port on the host
    used_host_ports = {f["host_port"] for f in port_data["forwards"] if f["protocol"] == protocol}
    host_port = None
    
    for _ in range(100): # Try 100 times
        random_p = random.randint(PORT_RANGE_START, PORT_RANGE_END)
        if random_p not in used_host_ports:
            host_port = random_p
            break
    
    if host_port is None:
        await interaction.followup.send(embed=create_error_embed(
            "No Free Ports",
            f"Could not find a free random port on the host for {protocol.upper()}. Please try again later or contact an admin."
        ), ephemeral=True)
        return
            
    # 4. Create the forward
    device_id = f"fwd-{protocol}-{host_port}" # Device name must be unique, use host port
    forward_id = str(int(time.time())) # Simple unique ID
    lxc_cmd = f"lxc config device add {container_name} {device_id} proxy listen={protocol}:{HOST_IP}:{host_port} connect={protocol}:127.0.0.1:{internal_port}"
    
    try:
        await execute_lxc(lxc_cmd)
        
        # 5. Store in database
        new_forward = {
            "id": forward_id,
            "owner_id": user_id,
            "container_name": container_name,
            "vps_num": vps_number,
            "device_id": device_id,
            "internal_port": internal_port, # Port inside container
            "host_port": host_port,       # Port on host IP
            "protocol": protocol
        }
        port_data["forwards"].append(new_forward)
        save_data()
        
        embed = create_success_embed("Port Forward Created", f"Successfully created port forward for `{container_name}`.")
        add_field(embed, "Rule ID", f"`{forward_id}`", True)
        add_field(embed, "Protocol", protocol.upper(), True)
        add_field(embed, "Slots Used", f"`{current_ports + 1}/{max_ports}`", True)
        add_field(embed, "Forwarding Rule", f"`{HOST_IP}:{host_port}` → `{container_name}:{internal_port}`", False)
        
        if internal_port == 22 and protocol == "tcp":
             add_field(embed, "SSH Example", f"```ssh root@{HOST_IP} -p {host_port}```", False)

        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        await interaction.followup.send(embed=create_error_embed("Forward Failed", f"An error occurred while creating the port forward: {str(e)}"))

@bot.tree.command(name='ports-list', description="List your active port forwards")
async def ports_list(interaction: discord.Interaction):
    # === IPV4 CHECK ===
    if not HOST_IP:
        await interaction.response.send_message(embed=create_error_embed(
            "IPv4 Not Configured",
            "The host server does not currently have an IPv4 address configured. Please contact an admin."
        ), ephemeral=True)
        return
    # ==================

    user_id = str(interaction.user.id)
    
    user_forwards = [f for f in port_data["forwards"] if f["owner_id"] == user_id]
    max_ports = port_data.get("users", {}).get(user_id, {}).get("max_ports", 0)
    
    embed = create_embed("My Port Forwards", f"You are currently using **{len(user_forwards)} / {max_ports}** available slots.")
    
    if not user_forwards:
        add_field(embed, "No Forwards", "You have no active port forwards. Use `/ports-add` to create one.")
    else:
        forward_list = []
        for f in user_forwards:
            forward_list.append(
                f"**ID:** `{f['id']}` | **VPS:** `{f['container_name']}`\n"
                f" ▸ `({f['protocol'].upper()})` `{HOST_IP}:{f['host_port']}` → `Container:{f['internal_port']}`"
            )
        add_field(embed, "Active Forwards", "\n".join(forward_list))
        
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name='ports-remove', description="Remove a port forward by its ID")
@app_commands.describe(forward_id="The ID of the port forward (from /ports-list)")
async def ports_remove(interaction: discord.Interaction, forward_id: str):
    # === IPV4 CHECK ===
    if not HOST_IP:
        await interaction.response.send_message(embed=create_error_embed(
            "IPv4 Not Configured",
            "The host server does not currently have an IPv4 address configured. Please contact an admin."
        ), ephemeral=True)
        return
    # ==================

    await interaction.response.defer()
    user_id = str(interaction.user.id)
    
    forward_to_remove = None
    for f in port_data["forwards"]:
        if f["id"] == forward_id:
            forward_to_remove = f
            break
            
    if not forward_to_remove:
        await interaction.followup.send(embed=create_error_embed("Not Found", f"No port forward found with ID: `{forward_id}`"), ephemeral=True)
        return
        
    # Check ownership
    if forward_to_remove["owner_id"] != user_id:
        await interaction.followup.send(embed=create_error_embed("Access Denied", "This is not your port forward. You cannot remove it."), ephemeral=True)
        return
        
    # Remove LXC device
    try:
        lxc_cmd = f"lxc config device remove {forward_to_remove['container_name']} {forward_to_remove['device_id']}"
        await execute_lxc(lxc_cmd)
    except Exception as e:
        logger.warning(f"Failed to remove LXC device {forward_to_remove['device_id']} from {forward_to_remove['container_name']}, but removing from DB anyway. Error: {e}")
        
    # Remove from DB
    port_data["forwards"].remove(forward_to_remove)
    save_data()
    
    await interaction.followup.send(embed=create_success_embed(
        "Port Forward Removed",
        f"Successfully removed forward rule `{forward_id}` (`{forward_to_remove['host_port']} -> {forward_to_remove['internal_port']}` {forward_to_remove['protocol'].upper()})."
    ))

@bot.tree.command(name='ports-revoke', description="Revoke specific port forward (Admin only)")
@app_commands.describe(forward_id="The ID of the port forward to revoke (from /vpsinfo or user)")
@app_commands.check(is_admin_check)
async def ports_revoke(interaction: discord.Interaction, forward_id: str):
    # === IPV4 CHECK ===
    if not HOST_IP:
        await interaction.response.send_message(embed=create_error_embed(
            "IPv4 Not Configured",
            "The host server does not currently have an IPv4 address configured. Please contact an admin."
        ), ephemeral=True)
        return
    # ==================

    await interaction.response.defer()
    
    forward_to_remove = None
    for f in port_data["forwards"]:
        if f["id"] == forward_id:
            forward_to_remove = f
            break
            
    if not forward_to_remove:
        await interaction.followup.send(embed=create_error_embed("Not Found", f"No port forward found with ID: `{forward_id}`"), ephemeral=True)
        return
        
    # (Admin) Skip ownership check
    
    # Remove LXC device
    try:
        lxc_cmd = f"lxc config device remove {forward_to_remove['container_name']} {forward_to_remove['device_id']}"
        await execute_lxc(lxc_cmd)
    except Exception as e:
        logger.warning(f"[ADMIN] Failed to remove LXC device {forward_to_remove['device_id']} from {forward_to_remove['container_name']}, but removing from DB anyway. Error: {e}")
        
    # Remove from DB
    port_data["forwards"].remove(forward_to_remove)
    save_data()
    
    owner = await bot.fetch_user(int(forward_to_remove['owner_id']))
    
    await interaction.followup.send(embed=create_success_embed(
        "Port Forward Revoked",
        f"Successfully revoked forward rule `{forward_id}` (`{forward_to_remove['host_port']} -> {forward_to_remove['internal_port']}` {forward_to_remove['protocol'].upper()}) owned by {owner.name}."
    ))

# ================================

# === START HELP COMMAND REWRITE ===

def get_help_embed(category: str):
    """Generates an embed for a specific help category."""
    
    embed = create_embed(f"📚 ZX-NODES Command Help", "ZX-NODES VPS Manager Commands:", 0x1a1a1a)
    
    if category == "user_vps":
        embed.title = "📚 User VPS Commands"
        commands_list = [
            ("`/myvps`", "List your VPS"),
            ("`/manage`", "Manage your VPS (start, stop, etc.)"),
            ("`/share-user <user> <vps_number>`", "Share VPS access"),
            ("`/share-ruser <user> <vps_number>`", "Revoke VPS access"),
            ("`/manage-shared <owner> <vps_number>`", "Manage a shared VPS")
        ]
        commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in commands_list])
        add_field(embed, "👤 User VPS Commands", commands_text, False)

    elif category == "user_ports":
        embed.title = "📚 User Port Commands"
        commands_list = [
            ("`/ports-add <vps_num> <internal_port> [prot]`", "Forward a random host port to your VPS's internal port"),
            ("`/ports-list`", "List your active port forwards"),
            ("`/ports-remove <id>`", "Remove one of your port forwards")
        ]
        commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in commands_list])
        add_field(embed, "🔌 Port Forwarding Commands", commands_text, False)

    elif category == "admin_vps":
        embed.title = "📚 Admin VPS Commands"
        commands_list = [
            ("`/lxc-list`", "List all LXC containers"),
            ("`/create <ram> <cpu> <disk> <user>`", "Create a custom VPS for a user"),
            ("`/delete-vps <user> <vps_num> [reason]`", "Delete a single VPS for a user"),
            ("`/delete-vps-some <user>`", "Select and delete multiple VPS for a user"),
            ("`/add-resources <vps_id> [ram] [cpu] [disk]`", "Add resources to a VPS"),
            ("`/resize-vps <container> [ram] [cpu] [disk]`", "Resize VPS resources"),
            ("`/suspend-vps <container> [reason]`", "Suspend a VPS"),
            ("`/unsuspend-vps <container>`", "Unsuspend a VPS"),
            ("`/suspension-logs [container]`", "View suspension logs"),
            ("`/userinfo <user>`", "Get detailed user information"),
            ("`/vps-uptime [user]`", "Show uptime for running VPS"),
            ("`/vps-top <cpu|ram>`", "Show top 5 VPS by resource usage"),
            ("`/serverstats`", "Show server statistics"),
            ("`/vpsinfo [container]`", "Get VPS information (admin)"),
            ("`/list-all`", "View all VPS and user information"),
            ("`/restart-vps <container>`", "Restart a VPS"),
            ("`/backup-vps <container>`", "Create a VPS snapshot"),
            ("`/restore-vps <container> <snapshot>`", "Restore VPS from snapshot"),
            ("`/list-snapshots <container>`", "List VPS snapshots"),
            ("`/exec <container> <command>`", "Execute command in VPS"),
            ("`/stop-vps-all`", "Stop all VPS (lxc stop --all --force)"),
            ("`/cpu-monitor <status|enable|disable>`", "Control CPU monitoring system"),
            ("`/clone-vps <container> <user> [new_name]`", "Clone a VPS for a new user"),
            ("`/migrate-vps <container> <pool>`", "Migrate VPS to another storage pool"),
            ("`/vps-stats <container>`", "Show VPS resource stats"),
            ("`/vps-network <container> <action> [value]`", "Manage VPS network (add/remove/limit)"),
            ("`/vps-processes <container>`", "List processes in VPS"),
            ("`/vps-logs <container> [lines]`", "Show VPS system logs")
        ]
        commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in commands_list])
        add_field(embed, "🛡️ VPS Management Commands", commands_text, False)

    elif category == "admin_ports":
        embed.title = "📚 Admin Port Commands"
        commands_list = [
            ("`/ports-add-user <amt> @user`", "Allocate port slots to a user"),
            ("`/ports-remove-user <amt> @user`", "Deallocate port slots from a user"),
            ("`/ports-revoke <id>`", "Revoke any port forward by ID")
        ]
        commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in commands_list])
        add_field(embed, "🛡️ Port Management Commands", commands_text, False)

    elif category == "main_admin":
        embed.title = "📚 Main Admin Commands"
        commands_list = [
            ("`/admin-add <user>`", "Promote user to Admin"),
            ("`/admin-remove <user>`", "Remove Admin privileges from user"),
            ("`/admin-list`", "List all Admins"),
            ("`/set-status <type> <name>`", "Set the bot's rich presence status")
        ]
        commands_text = "\n".join([f"**{cmd}** - {desc}" for cmd, desc in commands_list])
        add_field(embed, "👑 Main Admin Commands", commands_text, False)
        
    else: # Default (home)
        embed.description = "Please select a category from the menu below to view commands."
        add_field(embed, "General Commands (User)", "`/ping` - Check the bot's latency\n`/uptime` - Show the host's uptime")

    return embed


class HelpView(discord.ui.View):
    def __init__(self, interaction: discord.Interaction, is_admin: bool, is_main_admin: bool):
        super().__init__(timeout=180)
        self.original_interaction = interaction
        
        options = [
            discord.SelectOption(
                label="Main Page",
                description="Return to the main help page.",
                value="home",
                emoji="🏠"
            ),
            discord.SelectOption(
                label="User VPS Commands",
                description="Commands for managing your personal VPS.",
                value="user_vps",
                emoji="🖥️"
            ),
        ]
        
        # === IPV4 CHECK ===
        if HOST_IP:
            options.append(
                discord.SelectOption(
                    label="User Port Commands",
                    description="Commands for managing your port forwards.",
                    value="user_ports",
                    emoji="🔌"
                )
            )
        # ==================
        
        if is_admin:
            options.extend([
                discord.SelectOption(
                    label="Admin VPS Commands",
                    description="Commands for managing all users' VPS.",
                    value="admin_vps",
                    emoji="🛡️"
                ),
            ])
            
            # === IPV4 CHECK ===
            if HOST_IP:
                options.append(
                    discord.SelectOption(
                        label="Admin Port Commands",
                        description="Commands for managing users' port forwards.",
                        value="admin_ports",
                        emoji="🛡️"
                    )
                )
            # ==================
            
        if is_main_admin:
            options.append(
                discord.SelectOption(
                    label="Main Admin Commands",
                    description="Commands for managing Admins.",
                    value="main_admin",
                    emoji="👑"
                )
            )

        self.select_category = discord.ui.Select(
            placeholder="Select a category...",
            options=options
        )
        self.select_category.callback = self.select_callback
        self.add_item(self.select_category)

    async def select_callback(self, interaction: discord.Interaction):
        # Check if the user interacting is the one who initiated the command
        if interaction.user.id != self.original_interaction.user.id:
            await interaction.response.send_message("You cannot control this menu.", ephemeral=True)
            return
            
        category = self.select_category.values[0]
        new_embed = get_help_embed(category)
        await interaction.response.edit_message(embed=new_embed, view=self)

    async def on_timeout(self):
        # Disable the view on timeout
        try:
            for item in self.children:
                item.disabled = True
            await self.original_interaction.edit_original_response(view=self)
        except discord.NotFound:
            pass # Message was deleted


@bot.tree.command(name='help', description="Show ZX-NODES help information")
async def show_help(interaction: discord.Interaction):
    """Show ZX-NODES help information"""
    user_id = str(interaction.user.id)
    is_user_admin = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
    is_user_main_admin = user_id == str(MAIN_ADMIN_ID)

    # Create the initial embed
    initial_embed = get_help_embed("home")
    
    # Create the view with permissions
    view = HelpView(
        interaction=interaction, 
        is_admin=is_user_admin, 
        is_main_admin=is_user_main_admin
    )
    
    # Send the message publicly (ephemeral=False)
    await interaction.response.send_message(embed=initial_embed, view=view, ephemeral=False)


# === END HELP COMMAND REWRITE ===

# Command aliases for typos
@bot.tree.command(name='stats', description="Alias for /serverstats command (Admin only)")
@app_commands.check(is_admin_check)
async def stats_alias(interaction: discord.Interaction):
    """Alias for serverstats command"""
    # Simply call the server_stats function directly
    await server_stats(interaction)


# Run the bot with your token
if __name__ == "__main__":
    if DISCORD_TOKEN:
        bot.run(DISCORD_TOKEN)
    else:
        logger.error("No Discord token found in DISCORD_TOKEN environment variable.")
