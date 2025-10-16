# bot.py
import discord
from discord.ext import commands
from discord import app_commands, ui
import os
import random
import string
import asyncio
import datetime
import docker
import time
import logging
import aiohttp
import psutil
import platform
import shutil
import sqlite3
import pickle

# -------------------------
# Basic configuration
# -------------------------
from dotenv import load_dotenv
load_dotenv()

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('eaglenode_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('EagleNodeBot')

# Environment / defaults
TOKEN = os.getenv('DISCORD_TOKEN')
DEFAULT_OWNER_ID = int(os.getenv('OWNER_ID', '1405778722732376176'))
ADMIN_ROLE_ID = int(os.getenv('ADMIN_ROLE_ID', str(DEFAULT_OWNER_ID)))
ADMIN_IDS = {DEFAULT_OWNER_ID}
WATERMARK = "EagleNode VPS Service"
WELCOME_MESSAGE = "Welcome To EagleNode! Get Started With Us!"
MAX_VPS_PER_USER = int(os.getenv('MAX_VPS_PER_USER', '3'))
DEFAULT_OS_IMAGE = os.getenv('DEFAULT_OS_IMAGE', 'ubuntu:22.04')
DOCKER_NETWORK = os.getenv('DOCKER_NETWORK', 'bridge')
MAX_CONTAINERS = int(os.getenv('MAX_CONTAINERS', '100'))

# Files
DB_FILE = 'eaglenode.db'
BACKUP_FILE = 'eaglenode_backup.pkl'

# Miner patterns (left for anti-abuse)
MINER_PATTERNS = [
    'xmrig', 'ethminer', 'cgminer', 'sgminer', 'bfgminer',
    'minerd', 'cpuminer', 'cryptonight', 'stratum', 'pool'
]

# Dockerfile template (used if building custom images)
DOCKERFILE_TEMPLATE = """
FROM {base_image}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \\
    apt-get install -y systemd systemd-sysv dbus sudo \\
                       curl gnupg2 apt-transport-https ca-certificates \\
                       software-properties-common \\
                       docker.io openssh-server tmate && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN echo "root:{root_password}" | chpasswd

RUN useradd -m -s /bin/bash {username} && \\
    echo "{username}:{user_password}" | chpasswd && \\
    usermod -aG sudo {username}

RUN mkdir /var/run/sshd && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN systemctl enable ssh && \\
    systemctl enable docker

RUN echo '{welcome_message}' > /etc/motd && \\
    echo 'echo \"{welcome_message}\"' >> /home/{username}/.bashrc && \\
    echo '{watermark}' > /etc/machine-info && \\
    echo 'eaglenode-{vps_id}' > /etc/hostname

RUN apt-get update && \\
    apt-get install -y neofetch htop nano vim wget git tmux net-tools dnsutils iputils-ping && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
"""

# -------------------------
# Database abstraction
# -------------------------
class Database:
    def __init__(self, db_file=DB_FILE):
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()
        self._initialize_settings()

    def _create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vps_instances (
                token TEXT PRIMARY KEY,
                vps_id TEXT UNIQUE,
                container_id TEXT,
                memory INTEGER,
                cpu INTEGER,
                disk INTEGER,
                username TEXT,
                password TEXT,
                root_password TEXT,
                created_by TEXT,
                created_at TEXT,
                tmate_session TEXT,
                watermark TEXT,
                os_image TEXT,
                restart_count INTEGER DEFAULT 0,
                last_restart TEXT,
                status TEXT DEFAULT 'running',
                use_custom_image BOOLEAN DEFAULT 1
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS usage_stats (
                key TEXT PRIMARY KEY,
                value INTEGER DEFAULT 0
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS banned_users (
                user_id TEXT PRIMARY KEY
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                user_id TEXT PRIMARY KEY
            )
        ''')
        self.conn.commit()

    def _initialize_settings(self):
        defaults = {
            'max_containers': str(MAX_CONTAINERS),
            'max_vps_per_user': str(MAX_VPS_PER_USER)
        }
        for key, value in defaults.items():
            self.cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', (key, value))
        # load admin users
        self.cursor.execute('SELECT user_id FROM admin_users')
        for row in self.cursor.fetchall():
            try:
                ADMIN_IDS.add(int(row[0]))
            except:
                pass
        self.conn.commit()

    def get_setting(self, key, default=None):
        self.cursor.execute('SELECT value FROM system_settings WHERE key = ?', (key,))
        res = self.cursor.fetchone()
        return int(res[0]) if res else default

    def set_setting(self, key, value):
        self.cursor.execute('INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, str(value)))
        self.conn.commit()

    def get_stat(self, key, default=0):
        self.cursor.execute('SELECT value FROM usage_stats WHERE key = ?', (key,))
        res = self.cursor.fetchone()
        return res[0] if res else default

    def increment_stat(self, key, amount=1):
        current = self.get_stat(key, 0)
        self.cursor.execute('INSERT OR REPLACE INTO usage_stats (key, value) VALUES (?, ?)', (key, current + amount))
        self.conn.commit()

    def add_vps(self, vps_data: dict):
        columns = ', '.join(vps_data.keys())
        placeholders = ', '.join('?' for _ in vps_data)
        self.cursor.execute(f'INSERT INTO vps_instances ({columns}) VALUES ({placeholders})', tuple(vps_data.values()))
        self.conn.commit()
        self.increment_stat('total_vps_created', 1)

    def get_all_vps(self):
        self.cursor.execute('SELECT * FROM vps_instances')
        rows = self.cursor.fetchall()
        cols = [d[0] for d in self.cursor.description]
        return {row[0]: dict(zip(cols, row)) for row in rows}

    def get_vps_by_id(self, vps_id):
        self.cursor.execute('SELECT * FROM vps_instances WHERE vps_id = ?', (vps_id,))
        row = self.cursor.fetchone()
        if not row:
            return None, None
        cols = [d[0] for d in self.cursor.description]
        vps = dict(zip(cols, row))
        return vps['token'], vps

    def get_vps_by_token(self, token):
        self.cursor.execute('SELECT * FROM vps_instances WHERE token = ?', (token,))
        row = self.cursor.fetchone()
        if not row:
            return None
        cols = [d[0] for d in self.cursor.description]
        return dict(zip(cols, row))

    def remove_vps(self, token):
        self.cursor.execute('DELETE FROM vps_instances WHERE token = ?', (token,))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def update_vps(self, token, updates: dict):
        set_clause = ', '.join(f'{k} = ?' for k in updates.keys())
        values = list(updates.values()) + [token]
        self.cursor.execute(f'UPDATE vps_instances SET {set_clause} WHERE token = ?', values)
        self.conn.commit()
        return self.cursor.rowcount > 0

    def get_user_vps(self, user_id):
        self.cursor.execute('SELECT * FROM vps_instances WHERE created_by = ?', (str(user_id),))
        rows = self.cursor.fetchall()
        cols = [d[0] for d in self.cursor.description]
        return [dict(zip(cols, row)) for row in rows]

    def get_user_vps_count(self, user_id):
        self.cursor.execute('SELECT COUNT(*) FROM vps_instances WHERE created_by = ?', (str(user_id),))
        return self.cursor.fetchone()[0]

    def add_admin(self, user_id):
        self.cursor.execute('INSERT OR IGNORE INTO admin_users (user_id) VALUES (?)', (str(user_id),))
        self.conn.commit()
        ADMIN_IDS.add(int(user_id))

    def remove_admin(self, user_id):
        self.cursor.execute('DELETE FROM admin_users WHERE user_id = ?', (str(user_id),))
        self.conn.commit()
        if int(user_id) in ADMIN_IDS:
            ADMIN_IDS.remove(int(user_id))

    def get_admins(self):
        self.cursor.execute('SELECT user_id FROM admin_users')
        return [row[0] for row in self.cursor.fetchall()]

    def ban_user(self, user_id):
        self.cursor.execute('INSERT OR IGNORE INTO banned_users (user_id) VALUES (?)', (str(user_id),))
        self.conn.commit()

    def unban_user(self, user_id):
        self.cursor.execute('DELETE FROM banned_users WHERE user_id = ?', (str(user_id),))
        self.conn.commit()

    def is_user_banned(self, user_id):
        self.cursor.execute('SELECT 1 FROM banned_users WHERE user_id = ?', (str(user_id),))
        return self.cursor.fetchone() is not None

    def get_banned_users(self):
        self.cursor.execute('SELECT user_id FROM banned_users')
        return [row[0] for row in self.cursor.fetchall()]

    def backup_data(self):
        data = {
            'vps_instances': self.get_all_vps(),
            'usage_stats': {},
            'system_settings': {},
            'banned_users': self.get_banned_users(),
            'admin_users': self.get_admins()
        }
        self.cursor.execute('SELECT * FROM usage_stats')
        for row in self.cursor.fetchall():
            data['usage_stats'][row[0]] = row[1]
        self.cursor.execute('SELECT * FROM system_settings')
        for row in self.cursor.fetchall():
            data['system_settings'][row[0]] = row[1]
        with open(BACKUP_FILE, 'wb') as f:
            pickle.dump(data, f)
        return True

    def restore_data(self):
        if not os.path.exists(BACKUP_FILE):
            return False
        with open(BACKUP_FILE, 'rb') as f:
            data = pickle.load(f)
        self.cursor.execute('DELETE FROM vps_instances')
        self.cursor.execute('DELETE FROM usage_stats')
        self.cursor.execute('DELETE FROM system_settings')
        self.cursor.execute('DELETE FROM banned_users')
        self.cursor.execute('DELETE FROM admin_users')
        for token, vps in data.get('vps_instances', {}).items():
            cols = ', '.join(vps.keys())
            placeholders = ', '.join('?' for _ in vps)
            self.cursor.execute(f'INSERT INTO vps_instances ({cols}) VALUES ({placeholders})', tuple(vps.values()))
        for k, v in data.get('usage_stats', {}).items():
            self.cursor.execute('INSERT INTO usage_stats (key, value) VALUES (?, ?)', (k, v))
        for k, v in data.get('system_settings', {}).items():
            self.cursor.execute('INSERT INTO system_settings (key, value) VALUES (?, ?)', (k, v))
        for user_id in data.get('banned_users', []):
            self.cursor.execute('INSERT INTO banned_users (user_id) VALUES (?)', (user_id,))
        for user_id in data.get('admin_users', []):
            self.cursor.execute('INSERT INTO admin_users (user_id) VALUES (?)', (user_id,))
            try:
                ADMIN_IDS.add(int(user_id))
            except:
                pass
        self.conn.commit()
        return True

    def close(self):
        self.conn.close()

# -------------------------
# Utilities
# -------------------------
def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=24))

def generate_vps_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

def generate_ssh_password():
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choices(chars, k=16))

def has_admin_role(ctx):
    try:
        if isinstance(ctx, discord.Interaction):
            uid = ctx.user.id
            roles = getattr(ctx.user, "roles", [])
        else:
            uid = ctx.author.id
            roles = getattr(ctx.author, "roles", [])
    except:
        return False
    if uid in ADMIN_IDS:
        return True
    return any(getattr(r, 'id', None) == ADMIN_ROLE_ID for r in roles)

# -------------------------
# Docker helper functions
# -------------------------
async def run_docker_command(container_id, command, timeout=120):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_id, *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0:
            return False, stderr.decode()
        return True, stdout.decode()
    except asyncio.TimeoutError:
        return False, f"Command timed out after {timeout}s"
    except Exception as e:
        return False, str(e)

async def kill_apt_processes(container_id):
    try:
        await run_docker_command(container_id, ["bash", "-c", "killall apt apt-get dpkg || true"])
        await asyncio.sleep(1)
        await run_docker_command(container_id, ["bash", "-c", "rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*"])
        return True
    except:
        return False

async def capture_ssh_session_line(process):
    try:
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            text = line.decode('utf-8', errors='ignore').strip()
            if "ssh session:" in text:
                return text.split("ssh session:")[-1].strip()
        return None
    except Exception as e:
        logger.error(f"capture_ssh_session_line error: {e}")
        return None

async def build_custom_image(vps_id, username, root_password, user_password, base_image=DEFAULT_OS_IMAGE):
    temp_dir = f"temp_dockerfiles/{vps_id}"
    os.makedirs(temp_dir, exist_ok=True)
    dockerfile_content = DOCKERFILE_TEMPLATE.format(
        base_image=base_image,
        root_password=root_password,
        username=username,
        user_password=user_password,
        welcome_message=WELCOME_MESSAGE,
        watermark=WATERMARK,
        vps_id=vps_id
    )
    df_path = os.path.join(temp_dir, "Dockerfile")
    with open(df_path, 'w') as f:
        f.write(dockerfile_content)
    image_tag = f"eaglenode/{vps_id.lower()}:latest"
    proc = await asyncio.create_subprocess_exec(
        "docker", "build", "-t", image_tag, temp_dir,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    shutil.rmtree(temp_dir, ignore_errors=True)
    if proc.returncode != 0:
        raise Exception(f"docker build failed: {stderr.decode()}")
    return image_tag

# -------------------------
# Bot class
# -------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

class EagleNodeBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = Database(DB_FILE)
        self.session = None
        self.docker_client = None
        self.system_stats = {}
        self.loop.create_task(self._delayed_init())

    async def _delayed_init(self):
        await self.wait_until_ready()
        self.session = aiohttp.ClientSession()
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized")
        except Exception as e:
            logger.error(f"Could not initialize docker: {e}")
            self.docker_client = None

    async def close(self):
        await super().close()
        if self.session:
            await self.session.close()
        if self.docker_client:
            try:
                self.docker_client.close()
            except:
                pass
        self.db.close()

bot = EagleNodeBot(command_prefix='/', intents=intents, help_command=None)

# -------------------------
# Events
# -------------------------
@bot.event
async def on_ready():
    logger.info(f"{bot.user} connected as EagleNode Bot")
    try:
        await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="EagleNode VPS"))
        synced = await bot.tree.sync()
        logger.info(f"Synced {len(synced)} app commands")
    except Exception as e:
        logger.error(f"Error in on_ready: {e}")

# -------------------------
# Commands
# -------------------------
@bot.hybrid_command(name='help', description='Show all available commands')
async def show_commands(ctx):
    embed = discord.Embed(title="🤖 EagleNode VPS Bot Commands", color=discord.Color.blue())
    embed.add_field(name="User Commands", value="""
`/create_vps` - Create a new VPS (Admin only)
`/list` - List your EagleNode VPS instances
`/manage_vps <vps_id>` - Manage your VPS (start/stop/restart/info)
`/change_ssh_password <vps_id>` - Change SSH password
`/help` - Show this message
""", inline=False)
    if has_admin_role(ctx):
        embed.add_field(name="Admin Commands", value="""
`/vps_list` - List all VPS instances
`/delete_vps <vps_id>` - Delete a VPS
`/add_admin <user>` - Add a new admin
`/remove_admin <user>` - Remove an admin (Owner only)
`/list_admins` - List all admins
""", inline=False)
    await ctx.send(embed=embed, ephemeral=True)

@bot.hybrid_command(name='add_admin', description='Add a new admin (Admin only)')
@app_commands.describe(user="User to make admin")
async def add_admin(ctx, user: discord.User):
    if not has_admin_role(ctx):
        await ctx.send("❌ You must be an admin to use this command!", ephemeral=True)
        return
    bot.db.add_admin(user.id)
    await ctx.send(f"✅ {user.mention} has been added as an admin!", ephemeral=True)

@bot.hybrid_command(name='remove_admin', description='Remove an admin (Owner only)')
@app_commands.describe(user="User to remove from admin")
async def remove_admin(ctx, user: discord.User):
    if ctx.author.id != DEFAULT_OWNER_ID:
        await ctx.send("❌ Only the owner can remove admins!", ephemeral=True)
        return
    bot.db.remove_admin(user.id)
    await ctx.send(f"✅ {user.mention} removed from admins.", ephemeral=True)

@bot.hybrid_command(name='list_admins', description='List all admin users')
async def list_admins(ctx):
    if not has_admin_role(ctx):
        await ctx.send("❌ You must be an admin to use this command!", ephemeral=True)
        return
    embed = discord.Embed(title="Admin Users", color=discord.Color.blue())
    admin_list = []
    for admin_id in ADMIN_IDS:
        try:
            user = await bot.fetch_user(int(admin_id))
            admin_list.append(f"{user.name} ({user.id})")
        except:
            admin_list.append(f"Unknown ({admin_id})")
    for aid in bot.db.get_admins():
        if aid not in map(str, ADMIN_IDS):
            admin_list.append(aid)
    if not admin_list:
        embed.description = "No admins found"
    else:
        embed.description = "\n".join(sorted(set(admin_list)))
    await ctx.send(embed=embed, ephemeral=True)

@bot.hybrid_command(name='create_vps', description='Create a new VPS (Admin only)')
@app_commands.describe(
    memory="Memory in GB",
    cpu="CPU cores",
    disk="Disk GB",
    owner="User who will own the VPS",
    os_image="OS image to use",
    use_custom_image="Use custom image"
)
async def create_vps_command(ctx, memory: int, cpu: int, disk: int, owner: discord.Member,
                             os_image: str = DEFAULT_OS_IMAGE, use_custom_image: bool = True):
    if not has_admin_role(ctx):
        await ctx.send("❌ Admins only.", ephemeral=True)
        return
    if bot.db.is_user_banned(owner.id):
        await ctx.send("❌ This user is banned from creating VPS.", ephemeral=True)
        return
    if not bot.docker_client:
        await ctx.send("❌ Docker unavailable on the host.", ephemeral=True)
        return
    # Validate
    if memory < 1 or memory > 512:
        await ctx.send("Memory must be between 1 and 512 GB", ephemeral=True); return
    if cpu < 1 or cpu > 32:
        await ctx.send("CPU must be between 1 and 32 cores", ephemeral=True); return
    if disk < 10 or disk > 1000:
        await ctx.send("Disk must be between 10 and 1000 GB", ephemeral=True); return

    containers = bot.docker_client.containers.list(all=True)
    if len(containers) >= bot.db.get_setting('max_containers', MAX_CONTAINERS):
        await ctx.send("Container limit reached.", ephemeral=True); return

    if bot.db.get_user_vps_count(owner.id) >= bot.db.get_setting('max_vps_per_user', MAX_VPS_PER_USER):
        await ctx.send(f"{owner.mention} already has maximum VPS instances.", ephemeral=True); return

    status_msg = await ctx.send("🚀 Creating EagleNode VPS instance... This may take a little while.")
    vps_id = generate_vps_id()
    token = generate_token()
    username = owner.name.lower().replace(" ", "_")[:20]
    root_password = generate_ssh_password()
    user_password = generate_ssh_password()
    memory_bytes = memory * 1024 * 1024 * 1024

    try:
        if use_custom_image:
            await status_msg.edit(content="🔨 Building custom image...")
            image_tag = await build_custom_image(vps_id, username, root_password, user_password, os_image)
            await status_msg.edit(content="⚙️ Starting container from custom image...")
            container = bot.docker_client.containers.run(
                image_tag,
                detach=True,
                privileged=True,
                hostname=f"eaglenode-{vps_id}",
                mem_limit=memory_bytes,
                cpu_period=100000,
                cpu_quota=int(cpu * 100000),
                cap_add=["ALL"],
                network=DOCKER_NETWORK,
                volumes={f'eaglenode-{vps_id}': {'bind': '/data', 'mode': 'rw'}},
                restart_policy={"Name": "always"}
            )
        else:
            await status_msg.edit(content="⚙️ Starting container from base image...")
            try:
                container = bot.docker_client.containers.run(
                    os_image,
                    detach=True,
                    privileged=True,
                    hostname=f"eaglenode-{vps_id}",
                    mem_limit=memory_bytes,
                    cpu_period=100000,
                    cpu_quota=int(cpu * 100000),
                    cap_add=["ALL"],
                    command="tail -f /dev/null",
                    tty=True,
                    network=DOCKER_NETWORK,
                    volumes={f'eaglenode-{vps_id}': {'bind': '/data', 'mode': 'rw'}},
                    restart_policy={"Name": "always"}
                )
            except docker.errors.ImageNotFound:
                container = bot.docker_client.containers.run(
                    DEFAULT_OS_IMAGE,
                    detach=True,
                    privileged=True,
                    hostname=f"eaglenode-{vps_id}",
                    mem_limit=memory_bytes,
                    cpu_period=100000,
                    cpu_quota=int(cpu * 100000),
                    cap_add=["ALL"],
                    command="tail -f /dev/null",
                    tty=True,
                    network=DOCKER_NETWORK,
                    volumes={f'eaglenode-{vps_id}': {'bind': '/data', 'mode': 'rw'}},
                    restart_policy={"Name": "always"}
                )
                os_image = DEFAULT_OS_IMAGE

        await status_msg.edit(content="🔧 Finalizing container configuration...")
        await asyncio.sleep(3)

        # minimal setup: create user and set password
        try:
            cmds = [
                f"useradd -m -s /bin/bash {username}",
                f"echo '{username}:{user_password}' | chpasswd",
                f"usermod -aG sudo {username}",
                "sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config || true",
                "service ssh restart || true",
                f"echo '{WELCOME_MESSAGE}' > /etc/motd || true",
                f"echo '{WATERMARK}' > /etc/machine-info || true",
                f"echo 'eaglenode-{vps_id}' > /etc/hostname || true"
            ]
            for c in cmds:
                await run_docker_command(container.id, ["bash", "-c", c])
        except Exception as e:
            logger.warning(f"User setup warning: {e}")

        # attempt to start tmate session to capture (best-effort)
        tmate_session = None
        try:
            proc = await asyncio.create_subprocess_exec("docker", "exec", container.id, "tmate", "-F",
                                                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            tmate_session = await capture_ssh_session_line(proc)
        except Exception:
            tmate_session = None

        vps_data = {
            "token": token,
            "vps_id": vps_id,
            "container_id": container.id,
            "memory": memory,
            "cpu": cpu,
            "disk": disk,
            "username": username,
            "password": user_password,
            "root_password": root_password if use_custom_image else None,
            "created_by": str(owner.id),
            "created_at": str(datetime.datetime.now()),
            "tmate_session": tmate_session,
            "watermark": WATERMARK,
            "os_image": os_image,
            "restart_count": 0,
            "last_restart": None,
            "status": "running",
            "use_custom_image": use_custom_image
        }

        bot.db.add_vps(vps_data)

        try:
            embed = discord.Embed(
                title="🎉 EAGLENODE VPS Creation Successful",
                color=discord.Color.green()
            )
            embed.add_field(name="🆔 VPS ID", value=vps_id, inline=True)
            embed.add_field(name="💾 Memory", value=f"{memory} GB", inline=True)
            embed.add_field(name="⚡ CPU", value=f"{cpu} cores", inline=True)
            embed.add_field(name="💿 Disk", value=f"{disk} GB", inline=True)
            embed.add_field(name="👤 Username", value=username, inline=True)
            embed.add_field(name="🔑 User Password", value=f"||{user_password}||", inline=False)
            if use_custom_image:
                embed.add_field(name="🔑 Root Password", value=f"||{root_password}||", inline=False)
            if tmate_session:
                embed.add_field(name="🔒 Tmate Session", value=f"```{tmate_session}```", inline=False)
            embed.add_field(name="🔌 Direct SSH", value=f"```ssh {username}@<server-ip>```", inline=False)
            embed.add_field(
                name="ℹ️ Note",
                value="This is an **EAGLENODE VPS** instance. You can install and configure additional packages as needed.",
                inline=False
            )

            await owner.send(embed=embed)
            await status_msg.edit(content=f"✅ EAGLENODE VPS created for {owner.mention}. Connection details have been sent via DM.")
        except discord.Forbidden:
            await status_msg.edit(content=f"✅ VPS created for {owner.mention}, but I couldn't DM them. Please enable DMs.")

    except Exception as e:
        logger.error(f"Error creating VPS: {e}")
        await status_msg.edit(content=f"❌ Error creating VPS: {e}")
        try:
            if 'container' in locals():
                container.stop()
                container.remove()
        except:
            pass

@bot.hybrid_command(name='list', description='List all your EagleNode VPS instances')
async def list_vps(ctx):
    try:
        user_vps = bot.db.get_user_vps(ctx.author.id)
        if not user_vps:
            await ctx.send("You don't have any VPS instances.", ephemeral=True)
            return
        embed = discord.Embed(title="Your EagleNode VPS Instances", color=discord.Color.blue())
        for vps in user_vps:
            status = vps.get('status', 'Unknown').capitalize()
            embed.add_field(
                name=f"VPS {vps.get('vps_id', 'Unknown')}",
                value=f"Status: {status}\nMemory: {vps.get('memory', 'Unknown')}GB\nCPU: {vps.get('cpu', 'Unknown')} cores\nDisk: {vps.get('disk', 'Unknown')}GB\nUsername: {vps.get('username', 'Unknown')}\nCreated: {vps.get('created_at','Unknown')}",
                inline=False
            )
        await ctx.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"list_vps error: {e}")
        await ctx.send(f"❌ Error listing VPS: {e}", ephemeral=True)

@bot.hybrid_command(name='vps_list', description='List all VPS instances (Admin only)')
async def admin_list_vps(ctx):
    if not has_admin_role(ctx):
        await ctx.send("❌ Admins only.", ephemeral=True); return
    try:
        all_vps = bot.db.get_all_vps()
        if not all_vps:
            await ctx.send("No VPS instances found.", ephemeral=True); return
        embed = discord.Embed(title="All EAGLENODE VPS Instances", color=discord.Color.blue())
        for token, vps in all_vps.items():
            owner = "Unknown"
            try:
                owner_user = await bot.fetch_user(int(vps.get('created_by', '0')))
                owner = owner_user.name if owner_user else vps.get('created_by', 'Unknown')
            except:
                owner = vps.get('created_by', 'Unknown')
            embed.add_field(
                name=f"VPS {vps.get('vps_id', 'Unknown')}",
                value=f"Owner: {owner}\nStatus: {vps.get('status','Unknown')}\nMemory: {vps.get('memory','Unknown')}GB\nCPU: {vps.get('cpu','Unknown')}\nDisk: {vps.get('disk','Unknown')}GB\nCreated: {vps.get('created_at','Unknown')}",
                inline=False
            )
        await ctx.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"admin_list_vps error: {e}")
        await ctx.send(f"❌ Error: {e}", ephemeral=True)

@bot.hybrid_command(name='delete_vps', description='Delete a VPS instance (Admin only)')
@app_commands.describe(vps_id="ID of the VPS to delete")
async def delete_vps(ctx, vps_id: str):
    if not has_admin_role(ctx):
        await ctx.send("❌ Admins only.", ephemeral=True); return
    try:
        token, vps = bot.db.get_vps_by_id(vps_id)
        if not vps:
            await ctx.send("❌ VPS not found.", ephemeral=True); return
        try:
            if bot.docker_client and vps.get('container_id'):
                try:
                    cont = bot.docker_client.containers.get(vps['container_id'])
                    if cont.status == 'running':
                        cont.stop(timeout=5)
                    cont.remove()
                except docker.errors.NotFound:
                    pass
                except Exception as e:
                    logger.warning(f"Error removing container: {e}")
        except Exception as e:
            logger.warning(f"docker removal warning: {e}")
        bot.db.remove_vps(token)
        await ctx.send(f"✅ VPS {vps_id} deleted.", ephemeral=True)
    except Exception as e:
        logger.error(f"delete_vps error: {e}")
        await ctx.send(f"❌ Error deleting VPS: {e}", ephemeral=True)

@bot.hybrid_command(name='change_ssh_password', description='Change the SSH password for a VPS')
@app_commands.describe(vps_id="ID of the VPS to update")
async def change_ssh_password(ctx, vps_id: str):
    try:
        token, vps = bot.db.get_vps_by_id(vps_id)
        if not vps or vps.get('created_by') != str(ctx.author.id):
            await ctx.send("❌ VPS not found or you don't have access.", ephemeral=True); return
        if not bot.docker_client:
            await ctx.send("❌ Docker unavailable.", ephemeral=True); return
        try:
            cont = bot.docker_client.containers.get(vps['container_id'])
        except Exception:
            await ctx.send("❌ Container not found.", ephemeral=True); return
        new_password = generate_ssh_password()
        success, out = await run_docker_command(cont.id, ["bash", "-c", f"echo '{vps['username']}:{new_password}' | chpasswd"])
        if not success:
            await ctx.send(f"❌ Failed to change password: {out}", ephemeral=True); return
        bot.db.update_vps(token, {'password': new_password})
        embed = discord.Embed(title=f"SSH Password Updated for {vps_id}", color=discord.Color.green())
        embed.add_field(name="Username", value=vps['username'], inline=True)
        embed.add_field(name="New Password", value=f"||{new_password}||", inline=False)
        await ctx.author.send(embed=embed)
        await ctx.send("✅ SSH password changed. Check your DMs.", ephemeral=True)
    except Exception as e:
        logger.error(f"change_ssh_password error: {e}")
        await ctx.send(f"❌ Error: {e}", ephemeral=True)

# -------------------------
# Manage UI: View with buttons
# -------------------------
class ManageVPSView(ui.View):
    def __init__(self, token: str, vps: dict, author_id: int, timeout: int = 300):
        super().__init__(timeout=timeout)
        self.token = token
        self.vps = vps
        self.author_id = author_id

        self.start_button = ui.Button(label="Start", style=discord.ButtonStyle.green)
        self.stop_button = ui.Button(label="Stop", style=discord.ButtonStyle.danger)
        self.restart_button = ui.Button(label="Restart", style=discord.ButtonStyle.secondary)
        self.info_button = ui.Button(label="Info", style=discord.ButtonStyle.primary)
        self.delete_button = ui.Button(label="Delete (Admin)", style=discord.ButtonStyle.red)

        self.add_item(self.start_button)
        self.add_item(self.stop_button)
        self.add_item(self.restart_button)
        self.add_item(self.info_button)
        self.add_item(self.delete_button)

        self.start_button.callback = self.start_cb
        self.stop_button.callback = self.stop_cb
        self.restart_button.callback = self.restart_cb
        self.info_button.callback = self.info_cb
        self.delete_button.callback = self.delete_cb

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if str(interaction.user.id) == self.vps.get('created_by') or interaction.user.id in ADMIN_IDS or has_admin_role(interaction):
            return True
        await interaction.response.send_message("❌ You don't have permission to manage this VPS.", ephemeral=True)
        return False

    async def start_cb(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        try:
            if not bot.docker_client:
                await interaction.followup.send("Docker unavailable on host.", ephemeral=True); return
            cont = bot.docker_client.containers.get(self.vps['container_id'])
            if cont.status == 'running':
                await interaction.followup.send("VPS already running.", ephemeral=True); return
            cont.start()
            bot.db.update_vps(self.token, {'status': 'running'})
            await interaction.followup.send("✅ VPS started.", ephemeral=True)
        except Exception as e:
            logger.error(f"start_cb error: {e}")
            await interaction.followup.send(f"❌ Error starting VPS: {e}", ephemeral=True)

    async def stop_cb(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        try:
            if not bot.docker_client:
                await interaction.followup.send("Docker unavailable on host.", ephemeral=True); return
            cont = bot.docker_client.containers.get(self.vps['container_id'])
            if cont.status != 'running':
                await interaction.followup.send("VPS is not running.", ephemeral=True); return
            cont.stop(timeout=10)
            bot.db.update_vps(self.token, {'status': 'stopped'})
            await interaction.followup.send("✅ VPS stopped.", ephemeral=True)
        except Exception as e:
            logger.error(f"stop_cb error: {e}")
            await interaction.followup.send(f"❌ Error stopping VPS: {e}", ephemeral=True)

    async def restart_cb(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        try:
            if not bot.docker_client:
                await interaction.followup.send("Docker unavailable on host.", ephemeral=True); return
            cont = bot.docker_client.containers.get(self.vps['container_id'])
            cont.restart(timeout=15)
            bot.db.update_vps(self.token, {'restart_count': (self.vps.get('restart_count', 0) or 0) + 1, 'status': 'running', 'last_restart': str(datetime.datetime.now())})
            await interaction.followup.send("✅ VPS restarted.", ephemeral=True)
        except Exception as e:
            logger.error(f"restart_cb error: {e}")
            await interaction.followup.send(f"❌ Error restarting VPS: {e}", ephemeral=True)

    async def info_cb(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        try:
            cont_info = "Not available"
            if bot.docker_client:
                try:
                    cont = bot.docker_client.containers.get(self.vps['container_id'])
                    cont_info = f"Container status: {cont.status}\nImage: {cont.image.tags}\nCreated: {cont.attrs.get('Created')}"
                except Exception:
                    cont_info = "Container not found"
            embed = discord.Embed(title=f"EAGLENODE VPS {self.vps.get('vps_id')}", color=discord.Color.blue())
            embed.add_field(name="Owner", value=self.vps.get('created_by'), inline=True)
            embed.add_field(name="Status", value=self.vps.get('status'), inline=True)
            embed.add_field(name="Resources", value=f"{self.vps.get('memory')}GB / {self.vps.get('cpu')} cores / {self.vps.get('disk')}GB", inline=False)
            embed.add_field(name="Container Info", value=f"```\n{cont_info}\n```", inline=False)
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            logger.error(f"info_cb error: {e}")
            await interaction.followup.send(f"❌ Error fetching info: {e}", ephemeral=True)

    async def delete_cb(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        if not (interaction.user.id in ADMIN_IDS or has_admin_role(interaction) or interaction.user.id == DEFAULT_OWNER_ID):
            await interaction.followup.send("❌ Only admins can delete this VPS.", ephemeral=True); return
        try:
            token = self.token
            vps_id = self.vps.get('vps_id')
            if bot.docker_client:
                try:
                    cont = bot.docker_client.containers.get(self.vps['container_id'])
                    if cont.status == 'running':
                        cont.stop(timeout=5)
                    cont.remove()
                except Exception:
                    pass
            bot.db.remove_vps(token)
            await interaction.followup.send(f"✅ VPS {vps_id} has been deleted.", ephemeral=True)
        except Exception as e:
            logger.error(f"delete_cb error: {e}")
            await interaction.followup.send(f"❌ Error deleting VPS: {e}", ephemeral=True)

@bot.hybrid_command(name='manage_vps', description='Manage your VPS (start/stop/restart/info)')
@app_commands.describe(vps_id="ID of your VPS")
async def manage_vps(ctx, vps_id: str):
    try:
        token, vps = bot.db.get_vps_by_id(vps_id)
        if not vps:
            await ctx.send("❌ VPS not found.", ephemeral=True); return
        if str(ctx.author.id) != vps.get('created_by') and not has_admin_role(ctx):
            await ctx.send("❌ You don't have permission to manage this VPS.", ephemeral=True); return
        view = ManageVPSView(token, vps, ctx.author.id, timeout=300)
        embed = discord.Embed(title=f"Manage EAGLENODE VPS {vps_id}", color=discord.Color.blue())
        embed.add_field(name="Owner", value=vps.get('created_by'), inline=True)
        embed.add_field(name="Status", value=vps.get('status'), inline=True)
        embed.add_field(name="Resources", value=f"{vps.get('memory')}GB • {vps.get('cpu')} cores • {vps.get('disk')}GB", inline=False)
        await ctx.send(embed=embed, view=view, ephemeral=True)
    except Exception as e:
        logger.error(f"manage_vps error: {e}")
        await ctx.send(f"❌ Error: {e}", ephemeral=True)

# -------------------------
# Run the bot
# -------------------------
if __name__ == '__main__':
    if not TOKEN:
        logger.error("DISCORD_TOKEN not set in environment.")
    else:
        bot.run(TOKEN)
