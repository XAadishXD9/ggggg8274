import discord
from discord.ext import commands
from discord import ui, app_commands
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
import socket
import re
import psutil
import platform
import shutil
from typing import Optional, Literal
import sqlite3
import pickle
import base64
import threading
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit
import docker
import paramiko

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('eaglenode_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('EagleNodeBot')

# Load environment variables
load_dotenv()

# Bot configuration
TOKEN = os.getenv('DISCORD_TOKEN')
ADMIN_IDS = {int(id_) for id_ in os.getenv('ADMIN_IDS', '1405778722732376176').split(',') if id_.strip()}
ADMIN_ROLE_ID = int(os.getenv('ADMIN_ROLE_ID', '1405778722732376176'))
WATERMARK = "EagleNode VPS Service"
WELCOME_MESSAGE = "Welcome To EagleNode! Get Started With Us!"
MAX_VPS_PER_USER = int(os.getenv('MAX_VPS_PER_USER', '3'))
DEFAULT_OS_IMAGE = os.getenv('DEFAULT_OS_IMAGE', 'ubuntu:22.04')
DOCKER_NETWORK = os.getenv('DOCKER_NETWORK', 'bridge')
MAX_CONTAINERS = int(os.getenv('MAX_CONTAINERS', '100'))
DB_FILE = 'eaglenode.db'
BACKUP_FILE = 'eaglenode_backup.pkl'

MINER_PATTERNS = [
    'xmrig', 'ethminer', 'cgminer', 'sgminer', 'bfgminer',
    'minerd', 'cpuminer', 'cryptonight', 'stratum', 'pool'
]
# Dockerfile template for custom images
DOCKERFILE_TEMPLATE = """
FROM {base_image}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y systemd systemd-sysv dbus sudo \
                       curl gnupg2 apt-transport-https ca-certificates \
                       software-properties-common \
                       docker.io openssh-server tmate && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN echo "root:{root_password}" | chpasswd

RUN useradd -m -s /bin/bash {username} && \
    echo "{username}:{user_password}" | chpasswd && \
    usermod -aG sudo {username}

RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN systemctl enable ssh && \
    systemctl enable docker

RUN echo '{welcome_message}' > /etc/motd && \
    echo 'echo "{welcome_message}"' >> /home/{username}/.bashrc && \
    echo '{watermark}' > /etc/machine-info && \
    echo 'eaglenode-{vps_id}' > /etc/hostname

RUN apt-get update && \
    apt-get install -y neofetch htop nano vim wget git tmux net-tools dnsutils iputils-ping && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
"""

class Database:
    def __init__(self, db_file):
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
            self.cursor.execute(
                'INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)', (key, value)
            )

        self.cursor.execute('SELECT user_id FROM admin_users')
        for row in self.cursor.fetchall():
            ADMIN_IDS.add(int(row[0]))
        self.conn.commit()
# Initialize bot with command prefix '/'
class EagleNodeBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = Database(DB_FILE)
        self.session = None
        self.docker_client = None
        self.system_stats = {
            'cpu_usage': 0,
            'memory_usage': 0,
            'disk_usage': 0,
            'network_io': (0, 0),
            'last_updated': 0
        }
        self.my_persistent_views = {}

    async def setup_hook(self):
        self.session = aiohttp.ClientSession()
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized successfully")
            # start periodic system stats updater
            self.loop.create_task(self.update_system_stats())
            # Reconnect to existing containers
            await self.reconnect_containers()
            # Restore persistent views (if any)
            await self.restore_persistent_views()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            self.docker_client = None

    async def reconnect_containers(self):
        """Reconnect to existing containers on startup"""
        if not self.docker_client:
            return

        for token, vps in list(self.db.get_all_vps().items()):
            if vps['status'] == 'running':
                try:
                    container = self.docker_client.containers.get(vps['container_id'])
                    if container.status != 'running':
                        container.start()
                    logger.info(f"Reconnected and started container for VPS {vps['vps_id']}")
                except docker.errors.NotFound:
                    logger.warning(f"Container {vps['container_id']} not found, removing from data")
                    self.db.remove_vps(token)
                except Exception as e:
                    logger.error(f"Error reconnecting container {vps['vps_id']}: {e}")

    async def restore_persistent_views(self):
        """Restore persistent views after restart (placeholder)"""
        # Implement persistent view restoration if you use persistent UI components
        pass

    async def update_system_stats(self):
        """Update system statistics periodically"""
        await self.wait_until_ready()
        while not self.is_closed():
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)

                # Memory usage
                mem = psutil.virtual_memory()

                # Disk usage
                disk = psutil.disk_usage('/')

                # Network IO
                net_io = psutil.net_io_counters()

                self.system_stats = {
                    'cpu_usage': cpu_percent,
                    'memory_usage': mem.percent,
                    'memory_used': mem.used / (1024 ** 3),  # GB
                    'memory_total': mem.total / (1024 ** 3),  # GB
                    'disk_usage': disk.percent,
                    'disk_used': disk.used / (1024 ** 3),  # GB
                    'disk_total': disk.total / (1024 ** 3),  # GB
                    'network_sent': net_io.bytes_sent / (1024 ** 2),  # MB
                    'network_recv': net_io.bytes_recv / (1024 ** 2),  # MB
                    'last_updated': time.time()
                }
            except Exception as e:
                logger.error(f"Error updating system stats: {e}")
            await asyncio.sleep(30)

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

def generate_token():
    """Generate a random token for VPS access"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=24))

def generate_vps_id():
    """Generate a unique VPS ID"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

def generate_ssh_password():
    """Generate a random SSH password"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choices(chars, k=16))

def has_admin_role(ctx):
    """Check if user has admin role or is in ADMIN_IDS"""
    try:
        if isinstance(ctx, discord.Interaction):
            user_id = ctx.user.id
            roles = ctx.user.roles
        else:
            user_id = ctx.author.id
            roles = ctx.author.roles

        if user_id in ADMIN_IDS:
            return True

        return any(role.id == ADMIN_ROLE_ID for role in roles)
    except Exception:
        return False

async def capture_ssh_session_line(process):
    """Capture the SSH session line from tmate output"""
    try:
        # process is an asyncio.subprocess.Process
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            text = line.decode('utf-8', errors='ignore').strip()
            # tmate prints a session line; we try to find ssh or similar
            if "ssh session:" in text.lower() or "ssh" in text.lower() and "@" in text:
                return text
        return None
    except Exception as e:
        logger.error(f"Error capturing SSH session: {e}")
        return None

async def run_docker_command(container_id, command, timeout=120):
    """Run a Docker exec command asynchronously with timeout"""
    try:
        process = await asyncio.create_subprocess_exec(
            "docker", "exec", container_id, *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            if process.returncode != 0:
                return False, stderr.decode()
            return True, stdout.decode()
        except asyncio.TimeoutError:
            process.kill()
            return False, f"Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"Error running Docker command: {e}")
        return False, str(e)

async def kill_apt_processes(container_id):
    """Kill apt/dpkg processes and remove locks inside container"""
    try:
        await run_docker_command(container_id, ["bash", "-c", "killall apt apt-get dpkg || true"])
        await asyncio.sleep(1)
        await run_docker_command(container_id, ["bash", "-c", "rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* || true"])
        await asyncio.sleep(1)
        return True
    except Exception as e:
        logger.error(f"Error killing apt processes: {e}")
        return False

async def wait_for_apt_lock(container_id, status_msg):
    """Wait for apt lock to be released inside container"""
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            await kill_apt_processes(container_id)
            process = await asyncio.create_subprocess_exec(
                "docker", "exec", container_id, "bash", "-c", "lsof /var/lib/dpkg/lock-frontend || true",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if not stdout:
                return True
            # inform user if interaction provided
            if isinstance(status_msg, discord.Interaction):
                try:
                    await status_msg.followup.send(f"🔄 Waiting for package manager (attempt {attempt+1}/{max_attempts})...", ephemeral=True)
                except:
                    pass
            else:
                try:
                    await status_msg.edit(content=f"🔄 Waiting for package manager (attempt {attempt+1}/{max_attempts})...")
                except:
                    pass
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Error checking apt lock: {e}")
            await asyncio.sleep(5)
    return False

async def build_custom_image(vps_id, username, root_password, user_password, base_image=DEFAULT_OS_IMAGE):
    """Build a custom Docker image using the DOCKERFILE_TEMPLATE"""
    temp_dir = f"temp_dockerfiles/{vps_id}"
    try:
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
        with open(dockerfile_path, "w") as f:
            f.write(dockerfile_content)

        image_tag = f"eaglenode/{vps_id.lower()}:latest"
        build_process = await asyncio.create_subprocess_exec(
            "docker", "build", "-t", image_tag, temp_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await build_process.communicate()
        if build_process.returncode != 0:
            raise Exception(f"Failed to build image: {stderr.decode()}")
        return image_tag
    finally:
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
        except Exception as e:
            logger.error(f"Error cleaning temp dir: {e}")

async def setup_container(container_id, status_msg, memory, username, vps_id=None, use_custom_image=False):
    """Setup container: install packages, create user, configure SSH, set hostname, apply watermark"""
    try:
        # notify
        if isinstance(status_msg, discord.Interaction):
            await status_msg.followup.send("🔍 Checking container status...", ephemeral=True)
        else:
            try:
                await status_msg.edit(content="🔍 Checking container status...")
            except:
                pass

        container = bot.docker_client.containers.get(container_id)
        if container.status != "running":
            try:
                container.start()
                await asyncio.sleep(3)
            except Exception as e:
                logger.warning(f"Could not start container {container_id}: {e}")

        ssh_password = generate_ssh_password()

        if not use_custom_image:
            if isinstance(status_msg, discord.Interaction):
                await status_msg.followup.send("📦 Installing required packages...", ephemeral=True)
            else:
                try:
                    await status_msg.edit(content="📦 Installing required packages...")
                except:
                    pass

            success, out = await run_docker_command(container_id, ["apt-get", "update"])
            if not success:
                raise Exception(f"apt-get update failed: {out}")

            packages = [
                "tmate", "neofetch", "screen", "wget", "curl", "htop", "nano", "vim",
                "openssh-server", "sudo", "ufw", "git", "docker.io", "systemd", "systemd-sysv"
            ]
            success, out = await run_docker_command(container_id, ["apt-get", "install", "-y"] + packages, timeout=600)
            if not success:
                raise Exception(f"Package installation failed: {out}")

        # configure ssh user
        if not use_custom_image:
            user_cmds = [
                f"useradd -m -s /bin/bash {username} || true",
                f"echo '{username}:{ssh_password}' | chpasswd",
                f"usermod -aG sudo {username} || true",
                "sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config || true",
                "sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config || true",
                "service ssh restart || true"
            ]
            for c in user_cmds:
                success, out = await run_docker_command(container_id, ["bash", "-c", c])
                # don't raise on non-critical failures, but log them
                if not success:
                    logger.warning(f"Command failed in setup: {c} -> {out}")

        # set hostname and watermark
        if not vps_id:
            vps_id = generate_vps_id()
        hostname_cmd = f"echo 'eaglenode-{vps_id}' > /etc/hostname && hostname eaglenode-{vps_id}"
        await run_docker_command(container_id, ["bash", "-c", hostname_cmd])
        await run_docker_command(container_id, ["bash", "-c", f"echo '{WATERMARK}' > /etc/machine-info || true"])
        await run_docker_command(container_id, ["bash", "-c", f"echo '{WELCOME_MESSAGE}' > /etc/motd || true"])
        await run_docker_command(container_id, ["bash", "-c", f"chown -R {username}:{username} /home/{username} || true"])
        await run_docker_command(container_id, ["bash", "-c", f"chmod 700 /home/{username} || true"])

        # attempt to set memory limit (best-effort)
        try:
            memory_bytes = int(memory) * 1024 * 1024 * 1024
            await run_docker_command(container_id, ["bash", "-c", f"echo {memory_bytes} > /sys/fs/cgroup/memory.max || true"])
        except Exception:
            pass

        # final message
        if isinstance(status_msg, discord.Interaction):
            await status_msg.followup.send("✅ EagleNode VPS setup completed successfully!", ephemeral=True)
        else:
            try:
                await status_msg.edit(content="✅ EagleNode VPS setup completed successfully!")
            except:
                pass

        return True, ssh_password, vps_id
    except Exception as e:
        logger.error(f"Setup failed: {e}")
        if isinstance(status_msg, discord.Interaction):
            try:
                await status_msg.followup.send(f"❌ Setup failed: {e}", ephemeral=True)
            except:
                pass
        else:
            try:
                await status_msg.edit(content=f"❌ Setup failed: {e}")
            except:
                pass
        return False, None, None
        # ===============================
# Initialize the bot instance
# ===============================
bot = EagleNodeBot(
    command_prefix="/",
    intents=discord.Intents.all()
)

# -------------------------------
# Command: create_vps
# -------------------------------
@bot.hybrid_command(name="create_vps", description="Create a new EagleNode VPS")
@app_commands.describe(
    memory="Memory (GB)",
    cpu="CPU cores",
    disk="Disk size (GB)",
    os_image="OS image (optional)",
    use_custom_image="Use custom image setup (default: False)"
)
async def create_vps(ctx, memory: int, cpu: int, disk: int, os_image: Optional[str] = None, use_custom_image: bool = False):
    """Create a new VPS instance"""
    await ctx.defer(ephemeral=True)

    try:
        owner = ctx.author
        if bot.db.is_user_banned(owner.id):
            await ctx.send("❌ You are banned from creating VPS instances!", ephemeral=True)
            return

        # Check if user reached their VPS limit
        user_vps_count = bot.db.get_user_vps_count(owner.id)
        max_vps = bot.db.get_setting("max_vps_per_user")
        if user_vps_count >= max_vps:
            await ctx.send(f"❌ You have reached the maximum limit of {max_vps} VPS instances.", ephemeral=True)
            return

        vps_id = generate_vps_id()
        token = generate_token()
        username = f"user_{owner.id}"
        os_image = os_image or DEFAULT_OS_IMAGE
        memory_bytes = memory * 1024 * 1024 * 1024
        root_password = generate_ssh_password()

        status_msg = await ctx.send("🚀 Creating your EagleNode VPS... Please wait a few moments.")

        await asyncio.sleep(2)
        await status_msg.edit(content="📦 Setting up Docker container...")

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
                volumes={f"eaglenode-{vps_id}": {"bind": "/data", "mode": "rw"}},
                restart_policy={"Name": "always"}
            )
        except docker.errors.ImageNotFound:
            await status_msg.edit(content=f"⚠️ OS image `{os_image}` not found. Using default image `{DEFAULT_OS_IMAGE}` instead.")
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
                volumes={f"eaglenode-{vps_id}": {"bind": "/data", "mode": "rw"}},
                restart_policy={"Name": "always"}
            )
            os_image = DEFAULT_OS_IMAGE

        await status_msg.edit(content="🔧 Configuring your EagleNode VPS environment...")

        setup_success, ssh_password, _ = await setup_container(
            container.id, status_msg, memory, username, vps_id, use_custom_image=use_custom_image
        )
        if not setup_success:
            raise Exception("Failed to configure container environment.")

        exec_cmd = await asyncio.create_subprocess_exec(
            "docker", "exec", container.id, "tmate", "-F",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        ssh_session_line = await capture_ssh_session_line(exec_cmd)
        if not ssh_session_line:
            raise Exception("Failed to establish tmate SSH session.")

        # Save VPS data
        vps_data = {
            "token": token,
            "vps_id": vps_id,
            "container_id": container.id,
            "memory": memory,
            "cpu": cpu,
            "disk": disk,
            "username": username,
            "password": ssh_password,
            "root_password": root_password if use_custom_image else None,
            "created_by": str(owner.id),
            "created_at": str(datetime.datetime.now()),
            "tmate_session": ssh_session_line,
            "watermark": WATERMARK,
            "os_image": os_image,
            "restart_count": 0,
            "last_restart": None,
            "status": "running",
            "use_custom_image": use_custom_image
        }
        bot.db.add_vps(vps_data)

        embed = discord.Embed(title="🎉 EagleNode VPS Created Successfully!", color=discord.Color.green())
        embed.add_field(name="🆔 VPS ID", value=vps_id)
        embed.add_field(name="💾 Memory", value=f"{memory} GB")
        embed.add_field(name="⚡ CPU", value=f"{cpu} cores")
        embed.add_field(name="💿 Disk", value=f"{disk} GB")
        embed.add_field(name="👤 Username", value=username)
        embed.add_field(name="🔑 Password", value=f"||{ssh_password}||", inline=False)
        if use_custom_image:
            embed.add_field(name="Root Password", value=f"||{root_password}||", inline=False)
        embed.add_field(name="🔌 SSH Session", value=f"```{ssh_session_line}```", inline=False)
        embed.set_footer(text=WATERMARK)

        try:
            await owner.send(embed=embed)
            await status_msg.edit(content=f"✅ VPS ready! Check your DM, {owner.mention}.")
        except discord.Forbidden:
            await status_msg.edit(content="✅ VPS created, but I couldn't DM you. Please enable DMs from server members.")

    except Exception as e:
        logger.error(f"VPS creation failed: {e}")
        await ctx.send(f"❌ VPS creation failed: {e}", ephemeral=True)
        # Cleanup container on failure
        try:
            container.stop()
            container.remove()
        except Exception:
            # -------------------------------
# Command: list_vps (user)
# -------------------------------
@bot.hybrid_command(name="list", description="List all your EagleNode VPS instances")
async def list_vps(ctx):
    """List all VPS instances owned by the user"""
    try:
        user_vps = bot.db.get_user_vps(ctx.author.id)
        if not user_vps:
            await ctx.send("ℹ️ You don't have any VPS instances.", ephemeral=True)
            return

        embed = discord.Embed(title="Your EagleNode VPS Instances", color=discord.Color.blue())
        for vps in user_vps:
            try:
                container = bot.docker_client.containers.get(vps["container_id"]) if vps.get("container_id") else None
                status = container.status.capitalize() if container else "Not Found"
            except Exception:
                status = "Unknown"

            embed.add_field(
                name=f"VPS {vps['vps_id']}",
                value=f"**Status:** {status}\n"
                      f"**Memory:** {vps.get('memory')} GB\n"
                      f"**CPU:** {vps.get('cpu')} cores\n"
                      f"**Disk:** {vps.get('disk')} GB\n"
                      f"**Created:** {vps.get('created_at')}",
                inline=False
            )
        await ctx.send(embed=embed)
    except Exception as e:
        logger.error(f"list_vps error: {e}")
        await ctx.send(f"❌ Error listing VPS: {e}", ephemeral=True)

# -------------------------------
# Command: vps_list (admin)
# -------------------------------
@bot.hybrid_command(name="vps_list", description="List all VPS instances (Admin only)")
async def vps_list(ctx):
    if not has_admin_role(ctx):
        await ctx.send("❌ Admins only.", ephemeral=True)
        return

    try:
        all_vps = bot.db.get_all_vps()
        if not all_vps:
            await ctx.send("No VPS instances exist.", ephemeral=True)
            return

        embed = discord.Embed(title="All EagleNode VPS Instances", color=discord.Color.blurple())
        for token, vps in all_vps.items():
            owner = await bot.fetch_user(int(vps.get("created_by", "0"))) if vps.get("created_by") else None
            owner_name = owner.name if owner else "Unknown"

            embed.add_field(
                name=f"VPS {vps['vps_id']}",
                value=f"**Owner:** {owner_name}\n"
                      f"**CPU:** {vps.get('cpu')} cores\n"
                      f"**Memory:** {vps.get('memory')} GB\n"
                      f"**Disk:** {vps.get('disk')} GB\n"
                      f"**Status:** {vps.get('status','Unknown').capitalize()}",
                inline=False
            )
        await ctx.send(embed=embed)
    except Exception as e:
        logger.error(f"vps_list error: {e}")
        await ctx.send(f"❌ Error: {e}", ephemeral=True)

# -------------------------------
# Command: delete_vps (admin)
# -------------------------------
@bot.hybrid_command(name="delete_vps", description="Delete a VPS instance (Admin only)")
@app_commands.describe(vps_id="ID of the VPS to delete")
async def delete_vps(ctx, vps_id: str):
    if not has_admin_role(ctx):
        await ctx.send("❌ Admins only.", ephemeral=True)
        return

    try:
        token, vps = bot.db.get_vps_by_id(vps_id)
        if not vps:
            await ctx.send("❌ VPS not found.", ephemeral=True)
            return

        try:
            container = bot.docker_client.containers.get(vps["container_id"])
            container.stop()
            container.remove()
        except Exception as e:
            logger.warning(f"delete_vps: container cleanup failed: {e}")

        bot.db.remove_vps(token)
        await ctx.send(f"✅ VPS {vps_id} deleted successfully.")
    except Exception as e:
        logger.error(f"delete_vps error: {e}")
        await ctx.send(f"❌ Error deleting VPS: {e}", ephemeral=True)

# -------------------------------
# Command: connect_vps
# -------------------------------
@bot.hybrid_command(name="connect_vps", description="Reconnect to your VPS via tmate")
@app_commands.describe(token="Your VPS access token")
async def connect_vps(ctx, token: str):
    try:
        vps = bot.db.get_vps_by_token(token)
        if not vps:
            await ctx.send("❌ Invalid token.", ephemeral=True)
            return

        if str(ctx.author.id) != vps["created_by"] and not has_admin_role(ctx):
            await ctx.send("❌ You don't own this VPS.", ephemeral=True)
            return

        container = bot.docker_client.containers.get(vps["container_id"])
        if container.status != "running":
            container.start()
            await asyncio.sleep(3)

        exec_cmd = await asyncio.create_subprocess_exec(
            "docker", "exec", vps["container_id"], "tmate", "-F",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        ssh_session = await capture_ssh_session_line(exec_cmd)
        if not ssh_session:
            await ctx.send("❌ Couldn't get SSH session.", ephemeral=True)
            return

        bot.db.update_vps(token, {"tmate_session": ssh_session})

        embed = discord.Embed(title="EagleNode VPS SSH Access", color=discord.Color.green())
        embed.add_field(name="Username", value=vps["username"], inline=True)
        embed.add_field(name="Password", value=f"||{vps['password']}||", inline=True)
        embed.add_field(name="SSH Session", value=f"```{ssh_session}```", inline=False)
        await ctx.author.send(embed=embed)
        await ctx.send("✅ Check your DMs for SSH access.", ephemeral=True)
    except discord.Forbidden:
        await ctx.send("❌ Can't DM you. Enable DMs from server members.", ephemeral=True)
    except Exception as e:
        logger.error(f"connect_vps error: {e}")
        await ctx.send(f"❌ Error: {e}", ephemeral=True)
            pass
            # -------------------------------
# Command: vps_stats
# -------------------------------
@bot.hybrid_command(name="vps_stats", description="View live stats of your VPS")
@app_commands.describe(vps_id="VPS ID to check")
async def vps_stats(ctx, vps_id: str):
    try:
        token, vps = bot.db.get_vps_by_id(vps_id)
        if not vps or (vps["created_by"] != str(ctx.author.id) and not has_admin_role(ctx)):
            await ctx.send("❌ VPS not found or access denied.", ephemeral=True)
            return

        container = bot.docker_client.containers.get(vps["container_id"])
        if container.status != "running":
            await ctx.send("❌ VPS is not running.", ephemeral=True)
            return

        # Get system info from container
        mem_proc = await asyncio.create_subprocess_exec(
            "docker", "exec", vps["container_id"], "free", "-m",
            stdout=asyncio.subprocess.PIPE
        )
        cpu_proc = await asyncio.create_subprocess_exec(
            "docker", "exec", vps["container_id"], "top", "-bn1",
            stdout=asyncio.subprocess.PIPE
        )
        disk_proc = await asyncio.create_subprocess_exec(
            "docker", "exec", vps["container_id"], "df", "-h",
            stdout=asyncio.subprocess.PIPE
        )

        mem_out, _ = await mem_proc.communicate()
        cpu_out, _ = await cpu_proc.communicate()
        disk_out, _ = await disk_proc.communicate()

        embed = discord.Embed(title=f"VPS {vps_id} Resource Usage", color=discord.Color.blue())
        embed.add_field(name="Memory Info", value=f"```{mem_out.decode()[:800]}```", inline=False)
        embed.add_field(name="Disk Info", value=f"```{disk_out.decode()[:800]}```", inline=False)
        embed.add_field(name="Config", value=f"Memory: {vps['memory']}GB\nCPU: {vps['cpu']} cores\nDisk: {vps['disk']}GB", inline=False)

        await ctx.send(embed=embed)
    except Exception as e:
        logger.error(f"vps_stats error: {e}")
        await ctx.send(f"❌ Error fetching stats: {e}", ephemeral=True)

# -------------------------------
# Command: change_ssh_password
# -------------------------------
@bot.hybrid_command(name="change_ssh_password", description="Change SSH password for a VPS")
@app_commands.describe(vps_id="VPS ID to change password for")
async def change_ssh_password(ctx, vps_id: str):
    try:
        token, vps = bot.db.get_vps_by_id(vps_id)
        if not vps or vps["created_by"] != str(ctx.author.id):
            await ctx.send("❌ VPS not found or not yours.", ephemeral=True)
            return

        container = bot.docker_client.containers.get(vps["container_id"])
        if container.status != "running":
            await ctx.send("❌ VPS not running.", ephemeral=True)
            return

        new_pass = generate_ssh_password()
        await asyncio.create_subprocess_exec(
            "docker", "exec", vps["container_id"], "bash", "-c", f"echo '{vps['username']}:{new_pass}' | chpasswd"
        )

        bot.db.update_vps(token, {"password": new_pass})

        embed = discord.Embed(title=f"SSH Password Changed - VPS {vps_id}", color=discord.Color.green())
        embed.add_field(name="Username", value=vps["username"], inline=True)
        embed.add_field(name="New Password", value=f"||{new_pass}||", inline=True)
        await ctx.author.send(embed=embed)
        await ctx.send("✅ New SSH password sent to your DMs.", ephemeral=True)
    except Exception as e:
        logger.error(f"change_ssh_password error: {e}")
        await ctx.send(f"❌ Error changing password: {e}", ephemeral=True)

# -------------------------------
# Command: admin_stats
# -------------------------------
@bot.hybrid_command(name="admin_stats", description="System statistics (Admin only)")
async def admin_stats(ctx):
    if not has_admin_role(ctx):
        await ctx.send("❌ Admin only.", ephemeral=True)
        return

    try:
        containers = bot.docker_client.containers.list(all=True)
        stats = bot.system_stats

        embed = discord.Embed(title="EagleNode Host Stats", color=discord.Color.blurple())
        embed.add_field(name="VPS Instances", value=len(bot.db.get_all_vps()), inline=True)
        embed.add_field(name="Running Containers", value=len([c for c in containers if c.status == 'running']), inline=True)
        embed.add_field(name="CPU Usage", value=f"{stats['cpu_usage']}%", inline=True)
        embed.add_field(name="Memory Usage", value=f"{stats['memory_usage']}% of {stats['memory_total']:.2f}GB", inline=True)
        embed.add_field(name="Disk Usage", value=f"{stats['disk_usage']}% of {stats['disk_total']:.2f}GB", inline=True)
        embed.add_field(name="Network", value=f"Sent: {stats['network_sent']:.2f}MB / Recv: {stats['network_recv']:.2f}MB", inline=True)

        await ctx.send(embed=embed)
    except Exception as e:
        logger.error(f"admin_stats error: {e}")
        await ctx.send(f"❌ Error: {e}", ephemeral=True)

# -------------------------------
# Command: cleanup_vps (Admin)
# -------------------------------
@bot.hybrid_command(name="cleanup_vps", description="Remove stopped or missing VPS instances")
async def cleanup_vps(ctx):
    if not has_admin_role(ctx):
        await ctx.send("❌ Admin only.", ephemeral=True)
        return

    try:
        count = 0
        for token, vps in list(bot.db.get_all_vps().items()):
            try:
                container = bot.docker_client.containers.get(vps["container_id"])
                if container.status != "running":
                    container.remove(force=True)
                    bot.db.remove_vps(token)
                    count += 1
            except docker.errors.NotFound:
                bot.db.remove_vps(token)
                count += 1
        await ctx.send(f"✅ Cleaned up {count} inactive VPS instances.")
    except Exception as e:
        logger.error(f"cleanup_vps error: {e}")
        await ctx.send(f"❌ Error cleaning VPS: {e}", ephemeral=True)

# -------------------------------
# Command: vps_usage (user)
# -------------------------------
@bot.hybrid_command(name="vps_usage", description="View your VPS resource summary")
async def vps_usage(ctx):
    try:
        user_vps = bot.db.get_user_vps(ctx.author.id)
        total_memory = sum(vps["memory"] for vps in user_vps)
        total_cpu = sum(vps["cpu"] for vps in user_vps)
        total_disk = sum(vps["disk"] for vps in user_vps)

        embed = discord.Embed(title="Your EagleNode Usage", color=discord.Color.blue())
        embed.add_field(name="Total VPS", value=len(user_vps), inline=True)
        embed.add_field(name="Memory (GB)", value=total_memory, inline=True)
        embed.add_field(name="CPU Cores", value=total_cpu, inline=True)
        embed.add_field(name="Disk (GB)", value=total_disk, inline=True)
        await ctx.send(embed=embed)
    except Exception as e:
        logger.error(f"vps_usage error: {e}")
        await ctx.send(f"❌ Error fetching usage: {e}", ephemeral=True)
        # -------------------------------
# Interactive Management View
# -------------------------------
class VPSManagementView(discord.ui.View):
    def __init__(self, vps_id, container_id):
        super().__init__(timeout=300)
        self.vps_id = vps_id
        self.container_id = container_id
        self.original_message = None

    async def refresh_embed(self, interaction, status: str, color: discord.Color):
        token, vps = bot.db.get_vps_by_id(self.vps_id)
        embed = discord.Embed(
            title=f"EagleNode VPS Management - {self.vps_id}",
            color=color
        )
        embed.add_field(name="Status", value=status, inline=True)
        embed.add_field(name="Memory", value=f"{vps['memory']} GB", inline=True)
        embed.add_field(name="CPU", value=f"{vps['cpu']} cores", inline=True)
        embed.add_field(name="Disk", value=f"{vps['disk']} GB", inline=True)
        embed.add_field(name="Username", value=vps['username'], inline=True)
        await interaction.message.edit(embed=embed, view=self)

    @discord.ui.button(label="Start", style=discord.ButtonStyle.green)
    async def start(self, interaction: discord.Interaction, _):
        try:
            container = bot.docker_client.containers.get(self.container_id)
            container.start()
            bot.db.update_vps_by_id(self.vps_id, {"status": "running"})
            await self.refresh_embed(interaction, "🟢 Running", discord.Color.green())
            await interaction.response.send_message("✅ VPS started.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ {e}", ephemeral=True)

    @discord.ui.button(label="Stop", style=discord.ButtonStyle.red)
    async def stop(self, interaction: discord.Interaction, _):
        try:
            container = bot.docker_client.containers.get(self.container_id)
            container.stop()
            bot.db.update_vps_by_id(self.vps_id, {"status": "stopped"})
            await self.refresh_embed(interaction, "🔴 Stopped", discord.Color.orange())
            await interaction.response.send_message("✅ VPS stopped.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ {e}", ephemeral=True)

    @discord.ui.button(label="Restart", style=discord.ButtonStyle.blurple)
    async def restart(self, interaction: discord.Interaction, _):
        try:
            container = bot.docker_client.containers.get(self.container_id)
            container.restart()
            bot.db.update_vps_by_id(self.vps_id, {"status": "running"})
            await self.refresh_embed(interaction, "🔵 Restarted", discord.Color.blurple())
            await interaction.response.send_message("✅ VPS restarted.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ {e}", ephemeral=True)

    @discord.ui.button(label="Transfer", style=discord.ButtonStyle.gray)
    async def transfer(self, interaction: discord.Interaction, _):
        await interaction.response.send_modal(TransferVPSModal(self.vps_id))

# -------------------------------
# Transfer Modal
# -------------------------------
class TransferVPSModal(discord.ui.Modal, title="Transfer VPS"):
    def __init__(self, vps_id: str):
        super().__init__()
        self.vps_id = vps_id
        self.new_owner = discord.ui.TextInput(
            label="New owner ID or @mention",
            placeholder="Enter user ID or mention",
            required=True
        )
        self.add_item(self.new_owner)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            raw = self.new_owner.value.strip()
            if raw.startswith("<@") and raw.endswith(">"):
                new_owner_id = raw[2:-1].lstrip("!")
            else:
                new_owner_id = raw
            if not new_owner_id.isdigit():
                await interaction.response.send_message("❌ Invalid user ID.", ephemeral=True)
                return

            token, vps = bot.db.get_vps_by_id(self.vps_id)
            if not vps or vps["created_by"] != str(interaction.user.id):
                await interaction.response.send_message("❌ VPS not yours.", ephemeral=True)
                return

            new_owner = await bot.fetch_user(int(new_owner_id))
            bot.db.update_vps(token, {"created_by": str(new_owner.id)})

            await interaction.response.send_message(
                f"✅ VPS {self.vps_id} transferred to {new_owner.mention}.",
                ephemeral=True
            )

            try:
                embed = discord.Embed(title="EagleNode VPS Transferred to You", color=discord.Color.green())
                embed.add_field(name="VPS ID", value=self.vps_id)
                embed.add_field(name="Memory", value=f"{vps['memory']} GB")
                embed.add_field(name="CPU", value=f"{vps['cpu']} cores")
                embed.add_field(name="Username", value=vps['username'])
                embed.add_field(name="SSH Password", value=f"||{vps['password']}||", inline=False)
                await new_owner.send(embed=embed)
            except discord.Forbidden:
                pass
        except Exception as e:
            await interaction.response.send_message(f"❌ {e}", ephemeral=True)

# -------------------------------
# Command: manage_vps
# -------------------------------
@bot.hybrid_command(name="manage_vps", description="Open VPS management interface")
@app_commands.describe(vps_id="VPS ID to manage")
async def manage_vps(ctx, vps_id: str):
    try:
        token, vps = bot.db.get_vps_by_id(vps_id)
        if not vps or (vps["created_by"] != str(ctx.author.id) and not has_admin_role(ctx)):
            await ctx.send("❌ VPS not found or access denied.", ephemeral=True)
            return

        embed = discord.Embed(title=f"EagleNode VPS Management - {vps_id}", color=discord.Color.blurple())
        embed.add_field(name="Status", value=vps["status"], inline=True)
        embed.add_field(name="Memory", value=f"{vps['memory']} GB", inline=True)
        embed.add_field(name="CPU", value=f"{vps['cpu']} cores", inline=True)
        embed.add_field(name="Disk", value=f"{vps['disk']} GB", inline=True)
        embed.add_field(name="Username", value=vps["username"], inline=True)
        view = VPSManagementView(vps_id, vps["container_id"])
        msg = await ctx.send(embed=embed, view=view)
        view.original_message = msg
    except Exception as e:
        await ctx.send(f"❌ Error: {e}", ephemeral=True)
        # -------------------------------
# Command: help
# -------------------------------
@bot.hybrid_command(name="help", description="Show command categories")
async def help_command(ctx):
    embed = discord.Embed(title="🦅 EagleNode Bot Commands", color=discord.Color.gold())
    embed.add_field(
        name="User Commands",
        value=(
            "`/create_vps` - Create a VPS\n"
            "`/list` - List your VPS\n"
            "`/connect_vps` - Get SSH access\n"
            "`/vps_stats` - Check VPS stats\n"
            "`/vps_usage` - Your resource summary\n"
            "`/change_ssh_password` - Change SSH password\n"
            "`/manage_vps` - Control your VPS interactively"
        ),
        inline=False
    )
    embed.add_field(
        name="Admin Commands",
        value=(
            "`/delete_vps` - Delete VPS\n"
            "`/vps_list` - List all VPS\n"
            "`/admin_stats` - Show system stats\n"
            "`/cleanup_vps` - Clean stopped/missing VPS"
        ),
        inline=False
    )
    await ctx.send(embed=embed)

# -------------------------------
# Command Error Handler
# -------------------------------
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("❌ Command not found! Use `/help` to view commands.", ephemeral=True)
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Missing argument: `{error.param.name}`", ephemeral=True)
    elif isinstance(error, commands.CheckFailure):
        await ctx.send("❌ You don't have permission to use this command.", ephemeral=True)
    else:
        logger.error(f"Unhandled error: {error}")
        await ctx.send(f"❌ Unexpected error: {error}", ephemeral=True)

# -------------------------------
# Bot Startup Event
# -------------------------------
@bot.event
async def on_ready():
    try:
        synced = await bot.tree.sync()
        logger.info(f"✅ Synced {len(synced)} commands globally.")
    except Exception as e:
        logger.error(f"Command sync failed: {e}")

    logger.info(f"🟢 Logged in as {bot.user.name} (ID: {bot.user.id})")
    for guild in bot.guilds:
        logger.info(f"Connected to: {guild.name} (ID: {guild.id})")

    # Initialize Docker connection and database
    bot.docker_client = docker.from_env()
    bot.db.load()
    logger.info("✅ EagleNode database loaded successfully.")

    await bot.change_presence(
        activity=discord.Game(name="/create_vps | /help"),
        status=discord.Status.online
    )

# -------------------------------
# Shutdown Event
# -------------------------------
@bot.event
async def on_disconnect():
    logger.warning("⚠️ Bot disconnected from Discord.")

@bot.event
async def on_resumed():
    logger.info("🔁 Bot connection resumed.")

# -------------------------------
# Bot Entry Point
# -------------------------------
if __name__ == "__main__":
    try:
        os.makedirs("temp_dockerfiles", exist_ok=True)
        os.makedirs("backups", exist_ok=True)
        logger.info("🧱 Directories checked and created.")

        bot.run(TOKEN)
    except KeyboardInterrupt:
        logger.warning("🛑 Bot manually stopped.")
    except Exception as e:
        logger.error(f"🚨 Fatal Error: {e}")
        traceback.print_exc()
