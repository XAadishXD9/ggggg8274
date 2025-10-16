# eaglenode_bot.py
import discord
from discord.ext import commands
from discord import app_commands
import os
import random
import string
import json
import subprocess
from dotenv import load_dotenv
import asyncio
import datetime
import docker
import time
import logging
import traceback
import aiohttp
import psutil
import platform
import shutil
import sqlite3
import pickle

# -------------------------
# Basic configuration
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('eaglenode_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('EagleNodeBot')

load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
# ADMIN_IDS env var should be comma separated user ids
ADMIN_IDS = {int(id_.strip()) for id_ in os.getenv('ADMIN_IDS', '').split(',') if id_.strip().isdigit()}
ADMIN_ROLE_ID = int(os.getenv('ADMIN_ROLE_ID', '0')) if os.getenv('ADMIN_ROLE_ID') else 0

WATERMARK = "EAGLENODE VPS Service"
WELCOME_MESSAGE = "Welcome To EAGLENODE! Get Started With Us!"
MAX_VPS_PER_USER = int(os.getenv('MAX_VPS_PER_USER', '3'))
DEFAULT_OS_IMAGE = os.getenv('DEFAULT_OS_IMAGE', 'ubuntu:22.04')
DOCKER_NETWORK = os.getenv('DOCKER_NETWORK', 'bridge')
MAX_CONTAINERS = int(os.getenv('MAX_CONTAINERS', '100'))

DB_FILE = 'eaglenode.db'
BACKUP_FILE = 'eaglenode_backup.pkl'

# Miner detection patterns (basic)
MINER_PATTERNS = [
    'xmrig', 'ethminer', 'cgminer', 'sgminer', 'bfgminer',
    'minerd', 'cpuminer', 'cryptonight', 'stratum', 'pool'
]

# Dockerfile template for building a custom image (Debian/Ubuntu compatible)
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

RUN echo '{welcome_message}' > /etc/motd && \\
    echo 'echo \"{welcome_message}\"' >> /home/{username}/.bashrc && \\
    echo '{watermark}' > /etc/machine-info && \\
    echo 'eaglenode-{vps_id}' > /etc/hostname

RUN apt-get update && \\
    apt-get install -y neofetch htop nano vim wget git tmux net-tools dnsutils iputils-ping && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3

CMD ["/sbin/init"]
"""

# -------------------------
# Database helper
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
        for k, v in defaults.items():
            self.cursor.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', (k, v))
        # Load admin users into ADMIN_IDS set
        self.cursor.execute('SELECT user_id FROM admin_users')
        for row in self.cursor.fetchall():
            try:
                ADMIN_IDS.add(int(row[0]))
            except:
                pass
        self.conn.commit()

    def get_setting(self, key, default=None):
        self.cursor.execute('SELECT value FROM system_settings WHERE key = ?', (key,))
        r = self.cursor.fetchone()
        return int(r[0]) if r else default

    def set_setting(self, key, value):
        self.cursor.execute('INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, str(value)))
        self.conn.commit()

    def get_stat(self, key, default=0):
        self.cursor.execute('SELECT value FROM usage_stats WHERE key = ?', (key,))
        r = self.cursor.fetchone()
        return r[0] if r else default

    def increment_stat(self, key, amount=1):
        cur = self.get_stat(key, 0)
        self.cursor.execute('INSERT OR REPLACE INTO usage_stats (key, value) VALUES (?, ?)', (key, cur + amount))
        self.conn.commit()

    def add_vps(self, vps_data):
        columns = ', '.join(vps_data.keys())
        placeholders = ', '.join('?' for _ in vps_data)
        self.cursor.execute(f'INSERT INTO vps_instances ({columns}) VALUES ({placeholders})', tuple(vps_data.values()))
        self.conn.commit()
        self.increment_stat('total_vps_created')

    def remove_vps(self, token):
        self.cursor.execute('DELETE FROM vps_instances WHERE token = ?', (token,))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def update_vps(self, token, updates):
        set_clause = ', '.join(f'{k} = ?' for k in updates)
        values = list(updates.values()) + [token]
        self.cursor.execute(f'UPDATE vps_instances SET {set_clause} WHERE token = ?', values)
        self.conn.commit()
        return self.cursor.rowcount > 0

    def get_vps_by_token(self, token):
        self.cursor.execute('SELECT * FROM vps_instances WHERE token = ?', (token,))
        row = self.cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in self.cursor.description]
        return dict(zip(columns, row))

    def get_vps_by_id(self, vps_id):
        self.cursor.execute('SELECT * FROM vps_instances WHERE vps_id = ?', (vps_id,))
        row = self.cursor.fetchone()
        if not row:
            return None, None
        columns = [desc[0] for desc in self.cursor.description]
        d = dict(zip(columns, row))
        return d['token'], d

    def get_user_vps_count(self, user_id):
        self.cursor.execute('SELECT COUNT(*) FROM vps_instances WHERE created_by = ?', (str(user_id),))
        return self.cursor.fetchone()[0]

    def get_user_vps(self, user_id):
        self.cursor.execute('SELECT * FROM vps_instances WHERE created_by = ?', (str(user_id),))
        rows = self.cursor.fetchall()
        columns = [desc[0] for desc in self.cursor.description]
        return [dict(zip(columns, r)) for r in rows]

    def get_all_vps(self):
        self.cursor.execute('SELECT * FROM vps_instances')
        rows = self.cursor.fetchall()
        columns = [desc[0] for desc in self.cursor.description]
        return {r[0]: dict(zip(columns, r)) for r in rows}

    def add_admin(self, user_id):
        self.cursor.execute('INSERT OR IGNORE INTO admin_users (user_id) VALUES (?)', (str(user_id),))
        self.conn.commit()
        try:
            ADMIN_IDS.add(int(user_id))
        except:
            pass

    def remove_admin(self, user_id):
        self.cursor.execute('DELETE FROM admin_users WHERE user_id = ?', (str(user_id),))
        self.conn.commit()
        try:
            ADMIN_IDS.discard(int(user_id))
        except:
            pass

    def get_admins(self):
        self.cursor.execute('SELECT user_id FROM admin_users')
        return [r[0] for r in self.cursor.fetchall()]

    def backup_data(self, path=BACKUP_FILE):
        data = {
            'vps_instances': self.get_all_vps(),
            'usage_stats': {},
            'system_settings': {},
            'admin_users': self.get_admins()
        }
        self.cursor.execute('SELECT * FROM usage_stats')
        for row in self.cursor.fetchall():
            data['usage_stats'][row[0]] = row[1]
        self.cursor.execute('SELECT * FROM system_settings')
        for row in self.cursor.fetchall():
            data['system_settings'][row[0]] = row[1]

        with open(path, 'wb') as f:
            pickle.dump(data, f)
        return True

    def close(self):
        self.conn.close()

# -------------------------
# Utility helpers
# -------------------------
def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=24))

def generate_vps_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

def generate_ssh_password():
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choices(chars, k=16))

async def run_host_command(*cmd, timeout=120):
    """Run a host command asynchronously and return (success, stdout)"""
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            if proc.returncode != 0:
                return False, stderr.decode(errors='ignore')
            return True, stdout.decode(errors='ignore')
        except asyncio.TimeoutError:
            proc.kill()
            return False, f"Timed out after {timeout}s"
    except Exception as e:
        return False, str(e)

# -------------------------
# Bot class
# -------------------------
class EagleNodeBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = Database(DB_FILE)
        self.session = None
        self.docker_client = None
        self.system_stats = {}
        self.loop.create_task(self.startup_tasks())

    async def startup_tasks(self):
        await self.wait_until_ready()
        self.session = aiohttp.ClientSession()
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client ready")
        except Exception as e:
            logger.error(f"Cannot initialize Docker client: {e}")
            self.docker_client = None

        # Optionally: reconnect containers
        await self.reconnect_containers()

    async def reconnect_containers(self):
        if not self.docker_client:
            return
        for token, vps in list(self.db.get_all_vps().items()):
            try:
                if not vps.get('container_id'):
                    continue
                container = self.docker_client.containers.get(vps['container_id'])
                if container.status != 'running' and vps.get('status') == 'running':
                    container.start()
                    logger.info(f"Started container for {vps['vps_id']}")
            except Exception as e:
                logger.warning(f"Could not reconnect container for {vps.get('vps_id')}: {e}")

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

# -------------------------
# Helper functions for container setup
# -------------------------
async def capture_tmate_session(process):
    """Read tmate output lines and return ssh session when found"""
    try:
        # process is an asyncio subprocess with stdout
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            s = line.decode(errors='ignore').strip()
            if "ssh session:" in s.lower() or "ssh" in s.lower():
                return s
        return None
    except Exception as e:
        logger.error(f"capture_tmate_session error: {e}")
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
    dockerfile_path = os.path.join(temp_dir, "Dockerfile")
    with open(dockerfile_path, 'w') as f:
        f.write(dockerfile_content)
    image_tag = f"eaglenode/{vps_id.lower()}:latest"
    proc = await asyncio.create_subprocess_exec("docker", "build", "-t", image_tag, temp_dir, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()
    # Clean up
    try:
        shutil.rmtree(temp_dir)
    except:
        pass
    if proc.returncode != 0:
        raise Exception(stderr.decode(errors='ignore'))
    return image_tag

async def setup_container(container_id, status_msg, memory, username, vps_id=None, use_custom_image=False):
    """Perform in-container setup: create user, SSH, tmate, watermark, resource hints."""
    bot = global_bot  # assigned below
    try:
        # Ensure running
        if bot.docker_client:
            container = bot.docker_client.containers.get(container_id)
            if container.status != 'running':
                container.start()
                await asyncio.sleep(3)
        ssh_password = generate_ssh_password()
        # If container uses apt, install core packages (best-effort)
        if not use_custom_image:
            success, out = await run_host_command("docker", "exec", container_id, "bash", "-lc", "apt-get update -y")
            # attempt installations (non-fatal)
            _ = await run_host_command("docker", "exec", container_id, "bash", "-lc", "apt-get install -y tmate openssh-server sudo && systemctl restart ssh || true", timeout=300)
            # create user
            cmds = [
                f"useradd -m -s /bin/bash {username} || true",
                f"echo '{username}:{ssh_password}' | chpasswd || true",
                f"usermod -aG sudo {username} || true",
                "sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config || true",
                "sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config || true",
                "service ssh restart || true"
            ]
            for c in cmds:
                await run_host_command("docker", "exec", container_id, "bash", "-lc", c)
        # Set motd and watermark
        await run_host_command("docker", "exec", container_id, "bash", "-lc",
                               f"echo '{WELCOME_MESSAGE}' > /etc/motd || true")
        await run_host_command("docker", "exec", container_id, "bash", "-lc",
                               f"echo '{WATERMARK}' > /etc/machine-info || true")
        if not vps_id:
            vps_id = generate_vps_id()
        await run_host_command("docker", "exec", container_id, "bash", "-lc",
                               f"echo 'eaglenode-{vps_id}' > /etc/hostname || true && hostname eaglenode-{vps_id} || true")
        # memory hint (best-effort)
        try:
            memory_bytes = int(memory) * 1024 * 1024 * 1024
            await run_host_command("docker", "update", "--memory", str(memory_bytes), container_id)
        except Exception:
            pass
        return True, ssh_password
    except Exception as e:
        logger.error(f"setup_container failed: {e}")
        if isinstance(status_msg, discord.Message):
            try:
                await status_msg.edit(content=f"❌ Setup failed: {e}")
            except:
                pass
        return False, None

# -------------------------
# Global bot instance placeholder
# -------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
global_bot = EagleNodeBot(command_prefix='/', intents=intents, help_command=None)

# -------------------------
# Permission helpers
# -------------------------
def has_admin_role(ctx):
    try:
        if isinstance(ctx, discord.Interaction):
            user_id = ctx.user.id
            roles = getattr(ctx.user, 'roles', [])
        else:
            user_id = ctx.author.id
            roles = getattr(ctx.author, 'roles', [])
        if user_id in ADMIN_IDS:
            return True
        return any(getattr(r, "id", None) == ADMIN_ROLE_ID for r in roles)
    except Exception:
        return False

# -------------------------
# Events
# -------------------------
@global_bot.event
async def on_ready():
    logger.info(f"{global_bot.user} connected — EagleNode Bot ready.")
    try:
        await global_bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="EAGLENODE VPS"))
        try:
            await global_bot.tree.sync()
        except Exception:
            pass
    except Exception as e:
        logger.error(f"on_ready error: {e}")

# -------------------------
# Commands (kept)
# -------------------------
@global_bot.hybrid_command(name='help', description='Show all available commands')
async def show_commands(ctx):
    embed = discord.Embed(title="🤖 EAGLENODE VPS Bot Commands", color=discord.Color.blue())
    embed.add_field(name="User Commands", value="""
`/list` - List your VPS instances
`/manage_vps <vps_id>` - Manage your VPS (start/stop/restart/status)
`/change_ssh_password <vps_id>` - Change SSH password for your VPS
`/help` - Show this help message
""", inline=False)
    if has_admin_role(ctx):
        embed.add_field(name="Admin Commands", value="""
`/create_vps <memory> <cpu> <disk> <owner> [os_image] [use_custom_image]` - Create a new VPS
`/add_admin <user>` - Add a new admin
`/remove_admin <user>` - Remove an admin (Owner only)
`/list_admins` - List admin users
""", inline=False)
    await ctx.send(embed=embed, ephemeral=True)

@global_bot.hybrid_command(name='add_admin', description='Add a new admin (Admin only)')
@app_commands.describe(user="User to make admin")
async def add_admin(ctx, user: discord.User):
    if not has_admin_role(ctx):
        await ctx.send("❌ You must be an admin to use this command!", ephemeral=True)
        return
    global_bot.db.add_admin(user.id)
    await ctx.send(f"✅ {user.mention} has been added as an admin!", ephemeral=True)

@global_bot.hybrid_command(name='remove_admin', description='Remove an admin (Owner only)')
@app_commands.describe(user="User to remove from admin")
async def remove_admin(ctx, user: discord.User):
    # Owner-only: change the owner id here if needed
    owner_id = int(os.getenv('OWNER_ID', '0')) if os.getenv('OWNER_ID') else 0
    if ctx.author.id != owner_id:
        await ctx.send("❌ Only the owner can remove admins!", ephemeral=True)
        return
    global_bot.db.remove_admin(user.id)
    await ctx.send(f"✅ {user.mention} removed from admins.", ephemeral=True)

@global_bot.hybrid_command(name='list_admins', description='List all admin users')
async def list_admins(ctx):
    if not has_admin_role(ctx):
        await ctx.send("❌ You must be an admin to use this command!", ephemeral=True)
        return
    admin_list = []
    for admin_id in ADMIN_IDS:
        try:
            user = await global_bot.fetch_user(admin_id)
            admin_list.append(f"{user.name} ({admin_id})")
        except:
            admin_list.append(f"Unknown ({admin_id})")
    if ctx.guild and ADMIN_ROLE_ID:
        role = ctx.guild.get_role(ADMIN_ROLE_ID)
        if role:
            role_admins = [f"{m.name} ({m.id})" for m in role.members]
            admin_list.extend(role_admins)
    if not admin_list:
        await ctx.send("No admins found.", ephemeral=True)
    else:
        await ctx.send("**Admins:**\n" + "\n".join(sorted(set(admin_list))), ephemeral=True)

# -------------------------
# create_vps (admin only)
# -------------------------
@global_bot.hybrid_command(name='create_vps', description='Create a new VPS (Admin only)')
@app_commands.describe(
    memory="Memory in GB",
    cpu="CPU cores",
    disk="Disk space in GB",
    owner="User who will own the VPS",
    os_image="OS image to use (e.g. ubuntu:22.04)",
    use_custom_image="Use custom EagleNode image (recommended)"
)
async def create_vps_command(ctx, memory: int, cpu: int, disk: int, owner: discord.Member,
                             os_image: str = DEFAULT_OS_IMAGE, use_custom_image: bool = True):
    if not has_admin_role(ctx):
        await ctx.send("❌ You must be an admin to use this command!", ephemeral=True)
        return
    if not global_bot.docker_client:
        await ctx.send("❌ Docker not available on host.", ephemeral=True)
        return
    # Basic validation
    if memory < 1 or memory > 512:
        await ctx.send("❌ Memory must be between 1 and 512 GB", ephemeral=True); return
    if cpu < 1 or cpu > 64:
        await ctx.send("❌ CPU must be between 1 and 64 cores", ephemeral=True); return
    if disk < 10 or disk > 2000:
        await ctx.send("❌ Disk must be between 10 and 2000 GB", ephemeral=True); return
    if global_bot.db.get_user_vps_count(owner.id) >= global_bot.db.get_setting('max_vps_per_user', MAX_VPS_PER_USER):
        await ctx.send(f"❌ {owner.mention} already has the max number of VPS instances.", ephemeral=True); return

    status_msg = await ctx.send("🚀 Creating EagleNode VPS... This may take a few minutes.")
    vps_id = generate_vps_id()
    token = generate_token()
    username = owner.name.lower().replace(" ", "_")[:20]
    user_pw = generate_ssh_password()
    root_pw = generate_ssh_password() if use_custom_image else None

    try:
        # Build custom image if requested
        if use_custom_image:
            await status_msg.edit(content="🔨 Building custom Docker image (this may take several minutes)...")
            try:
                image_tag = await build_custom_image(vps_id, username, root_pw, user_pw, base_image=os_image)
            except Exception as e:
                await status_msg.edit(content=f"❌ Failed to build image: {e}")
                return
            await status_msg.edit(content="⚙️ Starting container from custom image...")
            mem_limit = f"{memory}g"
            container = global_bot.docker_client.containers.run(
                image_tag, detach=True, privileged=True,
                hostname=f"eaglenode-{vps_id}",
                mem_limit=mem_limit,
                network=DOCKER_NETWORK,
                volumes={f'eaglenode-{vps_id}': {'bind': '/data', 'mode': 'rw'}},
                restart_policy={"Name": "always"}
            )
            os_image_used = image_tag
        else:
            await status_msg.edit(content="⚙️ Starting container from base image...")
            mem_limit = f"{memory}g"
            try:
                container = global_bot.docker_client.containers.run(
                    os_image, detach=True, privileged=True, command="tail -f /dev/null",
                    hostname=f"eaglenode-{vps_id}", mem_limit=mem_limit,
                    network=DOCKER_NETWORK,
                    volumes={f'eaglenode-{vps_id}': {'bind': '/data', 'mode': 'rw'}},
                    restart_policy={"Name": "always"}
                )
                os_image_used = os_image
            except docker.errors.ImageNotFound:
                await status_msg.edit(content=f"⚠️ Image {os_image} not found. Using default {DEFAULT_OS_IMAGE}")
                container = global_bot.docker_client.containers.run(
                    DEFAULT_OS_IMAGE, detach=True, privileged=True, command="tail -f /dev/null",
                    hostname=f"eaglenode-{vps_id}", mem_limit=mem_limit,
                    network=DOCKER_NETWORK,
                    volumes={f'eaglenode-{vps_id}': {'bind': '/data', 'mode': 'rw'}},
                    restart_policy={"Name": "always"}
                )
                os_image_used = DEFAULT_OS_IMAGE

        await status_msg.edit(content="🔧 Configuring VPS inside container...")
        setup_success, ssh_pw = await setup_container(container.id, status_msg, memory, username, vps_id=vps_id, use_custom_image=use_custom_image)
        if not setup_success:
            raise Exception("Container setup failed.")
        # Start tmate to get a connection string
        await status_msg.edit(content="🔐 Starting tmate session for temporary access...")
        try:
            proc = await asyncio.create_subprocess_exec("docker", "exec", container.id, "tmate", "-F", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            tmate_session_line = await capture_tmate_session(proc)
            # don't wait indefinitely
            try:
                proc.kill()
            except:
                pass
        except Exception:
            tmate_session_line = None

        vps_data = {
            "token": token,
            "vps_id": vps_id,
            "container_id": container.id,
            "memory": memory,
            "cpu": cpu,
            "disk": disk,
            "username": username,
            "password": ssh_pw or user_pw,
            "root_password": root_pw,
            "created_by": str(owner.id),
            "created_at": str(datetime.datetime.now()),
            "tmate_session": tmate_session_line,
            "watermark": WATERMARK,
            "os_image": os_image_used,
            "restart_count": 0,
            "last_restart": None,
            "status": "running",
            "use_custom_image": use_custom_image
        }
        global_bot.db.add_vps(vps_data)

        # Send DM to owner with embed
        emb = discord.Embed(title="🎉 EAGLENODE VPS Creation Successful", color=discord.Color.green())
        emb.add_field(name="🆔 VPS ID", value=vps_id, inline=True)
        emb.add_field(name="💾 Memory", value=f"{memory} GB", inline=True)
        emb.add_field(name="⚡ CPU", value=f"{cpu} cores", inline=True)
        emb.add_field(name="💿 Disk", value=f"{disk} GB", inline=True)
        emb.add_field(name="👤 Username", value=username, inline=True)
        emb.add_field(name="🔑 User Password", value=f"||{ssh_pw or user_pw}||", inline=False)
        if use_custom_image and root_pw:
            emb.add_field(name="🔑 Root Password", value=f"||{root_pw}||", inline=False)
        if tmate_session_line:
            emb.add_field(name="🔒 Tmate Session", value=f"```{tmate_session_line}```", inline=False)
        emb.add_field(name="🔌 Direct SSH", value=f"```ssh {username}@<server-ip>```", inline=False)
        emb.add_field(name="ℹ️ Note", value="This is an EAGLENODE VPS instance. You can install and configure additional packages as needed.", inline=False)

        try:
            await owner.send(embed=emb)
            await status_msg.edit(content=f"✅ EAGLENODE VPS created for {owner.mention}. Check your DMs for connection details.")
        except discord.Forbidden:
            await status_msg.edit(content=f"❌ Created but I couldn't DM {owner.mention}. Enable DMs to receive details.")
    except Exception as e:
        logger.error(f"create_vps failed: {e}")
        await status_msg.edit(content=f"❌ Error creating VPS: {e}")
        # cleanup container if exists
        try:
            if 'container' in locals():
                container.stop()
                container.remove()
        except:
            pass

# -------------------------
# User commands: list, manage_vps, change_ssh_password
# -------------------------
@global_bot.hybrid_command(name='list', description='List all your VPS instances')
async def list_vps(ctx):
    try:
        user_vps = global_bot.db.get_user_vps(ctx.author.id)
        if not user_vps:
            await ctx.send("You don't have any VPS instances.", ephemeral=True); return
        embed = discord.Embed(title="Your EAGLENODE VPS Instances", color=discord.Color.blue())
        for vps in user_vps:
            status = vps.get('status', 'unknown').capitalize()
            embed.add_field(
                name=f"VPS {vps.get('vps_id')}",
                value=f"Status: {status}\nMemory: {vps.get('memory', 'Unknown')}GB\nCPU: {vps.get('cpu', 'Unknown')} cores\nDisk: {vps.get('disk', 'Unknown')}GB\nUsername: {vps.get('username', 'Unknown')}\nCreated: {vps.get('created_at', 'Unknown')}",
                inline=False
            )
        await ctx.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"list_vps error: {e}")
        await ctx.send(f"❌ Error listing VPS instances: {e}", ephemeral=True)

@global_bot.hybrid_command(name='manage_vps', description='Manage your VPS (start/stop/restart/status)')
@app_commands.describe(vps_id="ID of the VPS to manage", action="start | stop | restart | info")
async def manage_vps(ctx, vps_id: str, action: str = "info"):
    try:
        token, vps = global_bot.db.get_vps_by_id(vps_id)
        if not vps:
            await ctx.send("❌ VPS not found.", ephemeral=True); return
        if vps['created_by'] != str(ctx.author.id) and not has_admin_role(ctx):
            await ctx.send("❌ You don't have permission to manage this VPS.", ephemeral=True); return
        if not global_bot.docker_client:
            await ctx.send("❌ Docker not available.", ephemeral=True); return
        try:
            container = global_bot.docker_client.containers.get(vps['container_id'])
        except Exception:
            await ctx.send("❌ Container not found for this VPS.", ephemeral=True); return

        action = action.lower()
        if action == 'start':
            if container.status == 'running':
                await ctx.send("ℹ️ VPS is already running.", ephemeral=True)
            else:
                container.start()
                global_bot.db.update_vps(token, {'status': 'running'})
                await ctx.send("✅ VPS started.", ephemeral=True)
        elif action == 'stop':
            if container.status != 'running':
                await ctx.send("ℹ️ VPS is not running.", ephemeral=True)
            else:
                container.stop()
                global_bot.db.update_vps(token, {'status': 'stopped'})
                await ctx.send("✅ VPS stopped.", ephemeral=True)
        elif action == 'restart':
            container.restart()
            global_bot.db.update_vps(token, {'restart_count': vps.get('restart_count', 0) + 1, 'last_restart': str(datetime.datetime.now()), 'status': 'running'})
            await ctx.send("✅ VPS restarted.", ephemeral=True)
        else:  # info
            embed = discord.Embed(title=f"VPS {vps_id} Info", color=discord.Color.blue())
            embed.add_field(name="Status", value=vps.get('status', 'unknown'), inline=True)
            embed.add_field(name="Memory", value=f"{vps.get('memory', 'Unknown')}GB", inline=True)
            embed.add_field(name="CPU", value=f"{vps.get('cpu', 'Unknown')} cores", inline=True)
            embed.add_field(name="Disk", value=f"{vps.get('disk', 'Unknown')}GB", inline=True)
            embed.add_field(name="Username", value=vps.get('username', 'Unknown'), inline=True)
            embed.add_field(name="OS Image", value=vps.get('os_image', 'Unknown'), inline=True)
            await ctx.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"manage_vps error: {e}")
        await ctx.send(f"❌ Error managing VPS: {e}", ephemeral=True)

@global_bot.hybrid_command(name='change_ssh_password', description='Change the SSH password for a VPS')
@app_commands.describe(vps_id="ID of the VPS to update")
async def change_ssh_password(ctx, vps_id: str):
    try:
        token, vps = global_bot.db.get_vps_by_id(vps_id)
        if not vps:
            await ctx.send("❌ VPS not found.", ephemeral=True); return
        if vps['created_by'] != str(ctx.author.id) and not has_admin_role(ctx):
            await ctx.send("❌ You don't have permission to change password for this VPS.", ephemeral=True); return
        if not global_bot.docker_client:
            await ctx.send("❌ Docker not available.", ephemeral=True); return
        try:
            container = global_bot.docker_client.containers.get(vps['container_id'])
        except Exception:
            await ctx.send("❌ Container not found.", ephemeral=True); return
        if container.status != 'running':
            await ctx.send("❌ VPS is not running.", ephemeral=True); return
        new_pw = generate_ssh_password()
        cmd = f"echo '{vps['username']}:{new_pw}' | chpasswd"
        success, out = await run_host_command("docker", "exec", container.id, "bash", "-lc", cmd)
        if not success:
            raise Exception(out)
        global_bot.db.update_vps(token, {'password': new_pw})
        emb = discord.Embed(title=f"SSH Password Updated for {vps_id}", color=discord.Color.green())
        emb.add_field(name="Username", value=vps['username'], inline=True)
        emb.add_field(name="New Password", value=f"||{new_pw}||", inline=False)
        try:
            await ctx.author.send(embed=emb)
            await ctx.send("✅ SSH password updated. Check your DMs.", ephemeral=True)
        except discord.Forbidden:
            await ctx.send("✅ SSH password updated. I couldn't DM you — enable DMs to receive the password.", ephemeral=True)
    except Exception as e:
        logger.error(f"change_ssh_password error: {e}")
        await ctx.send(f"❌ Error changing SSH password: {e}", ephemeral=True)

# -------------------------
# Run the bot
# -------------------------
if __name__ == '__main__':
    # Expose global bot variable to helper functions
    global_bot = global_bot
    if TOKEN is None:
        logger.error("DISCORD_TOKEN is not set in environment. Exiting.")
    else:
        try:
            global_bot.run(TOKEN)
        except Exception as e:
            logger.error(f"Failed to start bot: {e}")
