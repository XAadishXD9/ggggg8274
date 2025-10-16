# ============================================================
#  EagleNode VPS Bot  (Part 1 / 4)
# ============================================================

import discord
from discord.ext import commands
from discord import app_commands, ui
import os, random, string, asyncio, datetime, docker, logging, aiohttp
import sqlite3, pickle, shutil, psutil, platform
from dotenv import load_dotenv

load_dotenv()

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("eaglenode_bot.log"), logging.StreamHandler()],
)
logger = logging.getLogger("EagleNodeBot")

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
TOKEN = os.getenv("DISCORD_TOKEN")
DEFAULT_OWNER_ID = int(os.getenv("OWNER_ID", "1405778722732376176"))
ADMIN_ROLE_ID = int(os.getenv("ADMIN_ROLE_ID", str(DEFAULT_OWNER_ID)))
ADMIN_IDS = {DEFAULT_OWNER_ID}
DB_FILE = "eaglenode.db"
BACKUP_FILE = "eaglenode_backup.pkl"
DEFAULT_OS_IMAGE = "ubuntu:22.04"
DOCKER_NETWORK = "bridge"
MAX_CONTAINERS = 100
MAX_VPS_PER_USER = 3
WELCOME_MESSAGE = "Welcome To EagleNode! Get Started With Us!"
WATERMARK = "EagleNode VPS Service"

# ------------------------------------------------------------
# Dockerfile template (used for custom image builds)
# ------------------------------------------------------------
DOCKERFILE_TEMPLATE = """
FROM {base_image}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y systemd sudo docker.io openssh-server tmate && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN echo "root:{root_password}" | chpasswd
RUN useradd -m -s /bin/bash {username} && \
    echo "{username}:{user_password}" | chpasswd && \
    usermod -aG sudo {username}
RUN mkdir /var/run/sshd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN echo '{welcome_message}' > /etc/motd && \
    echo '{watermark}' > /etc/machine-info && \
    echo 'eaglenode-{vps_id}' > /etc/hostname
CMD ["/sbin/init"]
"""

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------
def generate_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=24))

def generate_vps_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

def generate_ssh_password():
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choices(chars, k=16))

# ------------------------------------------------------------
# Database class
# ------------------------------------------------------------
class Database:
    def __init__(self, db_file=DB_FILE):
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.cur = self.conn.cursor()
        self._create_tables()
        self._load_admins()

    def _create_tables(self):
        self.cur.execute("""
        CREATE TABLE IF NOT EXISTS vps_instances(
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
        )""")
        self.cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_users(
            user_id TEXT PRIMARY KEY
        )""")
        self.conn.commit()

    def _load_admins(self):
        self.cur.execute("SELECT user_id FROM admin_users")
        for (uid,) in self.cur.fetchall():
            try:
                ADMIN_IDS.add(int(uid))
            except:
                pass

    def add_admin(self, uid:int):
        self.cur.execute("INSERT OR IGNORE INTO admin_users(user_id) VALUES(?)",(str(uid),))
        self.conn.commit()
        ADMIN_IDS.add(uid)

    def remove_admin(self, uid:int):
        self.cur.execute("DELETE FROM admin_users WHERE user_id=?",(str(uid),))
        self.conn.commit()
        ADMIN_IDS.discard(uid)

    def get_admins(self):
        self.cur.execute("SELECT user_id FROM admin_users")
        return [r[0] for r in self.cur.fetchall()]

    def add_vps(self, data:dict):
        cols = ','.join(data.keys())
        q = ','.join('?'*len(data))
        self.cur.execute(f"INSERT INTO vps_instances({cols}) VALUES({q})", tuple(data.values()))
        self.conn.commit()

    def get_vps_by_id(self, vps_id:str):
        self.cur.execute("SELECT * FROM vps_instances WHERE vps_id=?",(vps_id,))
        row = self.cur.fetchone()
        if not row: return None,None
        cols=[d[0] for d in self.cur.description]
        data=dict(zip(cols,row))
        return data['token'],data

    def get_user_vps(self, user_id:int):
        self.cur.execute("SELECT * FROM vps_instances WHERE created_by=?",(str(user_id),))
        rows=self.cur.fetchall()
        cols=[d[0] for d in self.cur.description]
        return [dict(zip(cols,r)) for r in rows]

    def get_all_vps(self):
        self.cur.execute("SELECT * FROM vps_instances")
        rows=self.cur.fetchall()
        cols=[d[0] for d in self.cur.description]
        return {r[0]:dict(zip(cols,r)) for r in rows}

    def remove_vps(self, token:str):
        self.cur.execute("DELETE FROM vps_instances WHERE token=?",(token,))
        self.conn.commit()

    def update_vps(self, token:str, updates:dict):
        set_clause=','.join(f"{k}=?" for k in updates)
        vals=list(updates.values())+[token]
        self.cur.execute(f"UPDATE vps_instances SET {set_clause} WHERE token=?", vals)
        self.conn.commit()

 # ============================================================
#  EagleNode VPS Bot  (Part 2 / 4)
# ============================================================

# ------------------------------------------------------------
# Permission helper
# ------------------------------------------------------------
def has_admin_role(ctx):
    try:
        uid = ctx.user.id if isinstance(ctx, discord.Interaction) else ctx.author.id
        roles = getattr(ctx.user if isinstance(ctx, discord.Interaction) else ctx.author, "roles", [])
    except:
        return False
    if uid in ADMIN_IDS:
        return True
    return any(getattr(r, 'id', None) == ADMIN_ROLE_ID for r in roles)

# ------------------------------------------------------------
# Docker helpers
# ------------------------------------------------------------
async def run_docker_command(container_id, command, timeout=90):
    """Run a command inside a container asynchronously."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_id, *command,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0:
            return False, stderr.decode()
        return True, stdout.decode()
    except asyncio.TimeoutError:
        return False, "Command timeout"
    except Exception as e:
        return False, str(e)

async def capture_tmate_line(process):
    """Capture tmate session line from output."""
    try:
        while True:
            line = await process.stdout.readline()
            if not line: break
            text = line.decode(errors="ignore").strip()
            if "ssh session:" in text:
                return text.split("ssh session:")[-1].strip()
        return None
    except Exception as e:
        logger.warning(f"capture_tmate_line error: {e}")
        return None

async def build_custom_image(vps_id, username, root_pw, user_pw, base_image=DEFAULT_OS_IMAGE):
    """Build a custom Docker image for VPS."""
    tmp = f"temp_dockerfiles/{vps_id}"
    os.makedirs(tmp, exist_ok=True)
    df_path = os.path.join(tmp, "Dockerfile")
    with open(df_path, "w") as f:
        f.write(DOCKERFILE_TEMPLATE.format(
            base_image=base_image,
            root_password=root_pw,
            username=username,
            user_password=user_pw,
            welcome_message=WELCOME_MESSAGE,
            watermark=WATERMARK,
            vps_id=vps_id
        ))
    image_tag = f"eaglenode/{vps_id.lower()}:latest"
    proc = await asyncio.create_subprocess_exec(
        "docker", "build", "-t", image_tag, tmp,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, err = await proc.communicate()
    shutil.rmtree(tmp, ignore_errors=True)
    if proc.returncode != 0:
        raise Exception(err.decode())
    return image_tag

# ------------------------------------------------------------
# Bot class with setup_hook (discord.py 2.4+ compatible)
# ------------------------------------------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

class EagleNodeBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = Database(DB_FILE)
        self.session = None
        self.docker_client = None

    async def setup_hook(self):
        """Initialize resources after loop is ready."""
        self.session = aiohttp.ClientSession()
        try:
            self.docker_client = docker.from_env()
            logger.info("🐳 Docker client initialized")
        except Exception as e:
            logger.error(f"Docker init failed: {e}")
            self.docker_client = None
        logger.info("🦅 EagleNode setup complete")

    async def close(self):
        """Graceful shutdown."""
        if self.session:
            await self.session.close()
        if self.docker_client:
            try:
                self.docker_client.close()
            except:
                pass
        self.db.conn.close()
        await super().close()

# ------------------------------------------------------------
# Initialize bot
# ------------------------------------------------------------
bot = EagleNodeBot(command_prefix="/", intents=intents, help_command=None)

# ------------------------------------------------------------
# Events
# ------------------------------------------------------------
@bot.event
async def on_ready():
    logger.info(f"✅ Logged in as {bot.user}")
    try:
        await bot.change_presence(activity=discord.Game("Managing EagleNode VPS"))
        synced = await bot.tree.sync()
        logger.info(f"Synced {len(synced)} commands.")
    except Exception as e:
        logger.error(f"on_ready error: {e}")   

# ============================================================
#  EagleNode VPS Bot  (Part 3 / 4)
# ============================================================

# ------------------------------------------------------------
# /help command
# ------------------------------------------------------------
@bot.hybrid_command(name="help", description="Show available EagleNode commands")
async def show_help(ctx):
    embed = discord.Embed(title="🦅 EagleNode Bot Commands", color=discord.Color.blue())
    embed.add_field(
        name="👤 User Commands",
        value=(
            "`/help` – Show this menu\n"
            "`/list` – List your VPS instances\n"
            "`/manage_vps <vps_id>` – Manage a VPS (Start/Stop/Restart/Info)\n"
            "`/change_ssh_password <vps_id>` – Change SSH password"
        ),
        inline=False
    )
    if has_admin_role(ctx):
        embed.add_field(
            name="🛠️ Admin Commands",
            value=(
                "`/create_vps` – Create a new VPS for a user\n"
                "`/vps_list` – List all VPS instances\n"
                "`/delete_vps <vps_id>` – Delete a VPS\n"
                "`/add_admin <user>` – Grant admin role\n"
                "`/remove_admin <user>` – Remove admin role (Owner only)\n"
                "`/list_admins` – Show admins"
            ),
            inline=False
        )
    await ctx.send(embed=embed, ephemeral=True)

# ------------------------------------------------------------
# Admin management
# ------------------------------------------------------------
@bot.hybrid_command(name="add_admin", description="Add a new admin (Admin only)")
@app_commands.describe(user="User to add")
async def add_admin(ctx, user: discord.User):
    if not has_admin_role(ctx):
        return await ctx.send("❌ Admins only", ephemeral=True)
    bot.db.add_admin(user.id)
    await ctx.send(f"✅ {user.mention} added as admin", ephemeral=True)

@bot.hybrid_command(name="remove_admin", description="Remove an admin (Owner only)")
@app_commands.describe(user="User to remove")
async def remove_admin(ctx, user: discord.User):
    if ctx.author.id != DEFAULT_OWNER_ID:
        return await ctx.send("❌ Only the owner can remove admins", ephemeral=True)
    bot.db.remove_admin(user.id)
    await ctx.send(f"✅ {user.mention} removed from admins", ephemeral=True)

@bot.hybrid_command(name="list_admins", description="List admins")
async def list_admins(ctx):
    if not has_admin_role(ctx):
        return await ctx.send("❌ Admins only", ephemeral=True)
    ids = bot.db.get_admins()
    embed = discord.Embed(title="🧑‍💻 Admin Users", color=discord.Color.purple())
    if not ids:
        embed.description = "_No admins yet_"
    else:
        desc = ""
        for i in ids:
            try:
                user = await bot.fetch_user(int(i))
                desc += f"• {user.name} (`{i}`)\n"
            except:
                desc += f"• Unknown (`{i}`)\n"
        embed.description = desc
    await ctx.send(embed=embed, ephemeral=True)

# ------------------------------------------------------------
# /create_vps  (Admin only)
# ------------------------------------------------------------
@bot.hybrid_command(name="create_vps", description="Create a new VPS (Admin only)")
@app_commands.describe(
    memory="Memory (GB)", cpu="CPU cores", disk="Disk (GB)",
    owner="Owner user", os_image="Base OS image", use_custom_image="Build custom image"
)
async def create_vps(ctx, memory:int, cpu:int, disk:int, owner:discord.Member,
                     os_image:str=DEFAULT_OS_IMAGE, use_custom_image:bool=True):
    if not has_admin_role(ctx):
        return await ctx.send("❌ Admins only", ephemeral=True)
    if not bot.docker_client:
        return await ctx.send("❌ Docker unavailable", ephemeral=True)

    status = await ctx.send("🚀 Creating EAGLENODE VPS...")
    vps_id = generate_vps_id()
    token = generate_token()
    username = owner.name.lower().replace(" ", "_")[:20]
    root_pw = generate_ssh_password()
    user_pw = generate_ssh_password()
    mem_bytes = memory * 1024**3

    try:
        # --- create container ---
        if use_custom_image:
            await status.edit(content="🔨 Building image...")
            image_tag = await build_custom_image(vps_id, username, root_pw, user_pw, os_image)
            container = bot.docker_client.containers.run(
                image_tag, detach=True, privileged=True,
                hostname=f"eaglenode-{vps_id}", mem_limit=mem_bytes,
                cpu_quota=int(cpu*100000), cpu_period=100000,
                network=DOCKER_NETWORK, tty=True,
                volumes={f"eaglenode-{vps_id}": {"bind": "/data", "mode": "rw"}},
                restart_policy={"Name":"always"}
            )
        else:
            container = bot.docker_client.containers.run(
                os_image, detach=True, privileged=True,
                hostname=f"eaglenode-{vps_id}", mem_limit=mem_bytes,
                cpu_quota=int(cpu*100000), cpu_period=100000,
                command="tail -f /dev/null", tty=True,
                network=DOCKER_NETWORK, restart_policy={"Name":"always"}
            )

        # --- post-setup ---
        cmds = [
            f"useradd -m -s /bin/bash {username}",
            f"echo '{username}:{user_pw}' | chpasswd",
            "service ssh restart || true"
        ]
        for c in cmds:
            await run_docker_command(container.id, ["bash", "-c", c])

        # Try tmate
        tmate_session=None
        try:
            proc=await asyncio.create_subprocess_exec(
                "docker","exec",container.id,"tmate","-F",
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            tmate_session=await capture_tmate_line(proc)
        except: pass

        vps_data={
            "token":token,"vps_id":vps_id,"container_id":container.id,
            "memory":memory,"cpu":cpu,"disk":disk,
            "username":username,"password":user_pw,
            "root_password":root_pw if use_custom_image else None,
            "created_by":str(owner.id),"created_at":str(datetime.datetime.now()),
            "tmate_session":tmate_session,"watermark":WATERMARK,
            "os_image":os_image,"status":"running",
            "use_custom_image":use_custom_image
        }
        bot.db.add_vps(vps_data)

        # Embed DM
        emb=discord.Embed(
            title="🎉 EAGLENODE VPS Creation Successful",
            color=discord.Color.green()
        )
        emb.add_field(name="🆔 VPS ID",value=vps_id,inline=True)
        emb.add_field(name="💾 Memory",value=f"{memory} GB",inline=True)
        emb.add_field(name="⚡ CPU",value=f"{cpu} cores",inline=True)
        emb.add_field(name="💿 Disk",value=f"{disk} GB",inline=True)
        emb.add_field(name="👤 Username",value=username,inline=True)
        emb.add_field(name="🔑 User Password",value=f"||{user_pw}||",inline=False)
        if use_custom_image:
            emb.add_field(name="🔑 Root Password",value=f"||{root_pw}||",inline=False)
        if tmate_session:
            emb.add_field(name="🔒 Tmate Session",value=f"```{tmate_session}```",inline=False)
        emb.add_field(name="🔌 Direct SSH",value=f"```ssh {username}@<server-ip>```",inline=False)
        emb.add_field(name="ℹ️ Note",value="This is an EAGLENODE VPS instance.",inline=False)
        try:
            await owner.send(embed=emb)
            await status.edit(content=f"✅ Created for {owner.mention}, details sent via DM.")
        except discord.Forbidden:
            await status.edit(content=f"✅ Created for {owner.mention} (but DM blocked).")

    except Exception as e:
        await status.edit(content=f"❌ Error: {e}"                                                    

# ============================================================
#  EagleNode VPS Bot  (Part 4 / 4)
# ============================================================

# ------------------------------------------------------------
# /list  –  show user's VPS
# ------------------------------------------------------------
@bot.hybrid_command(name="list", description="List your EagleNode VPS instances")
async def list_vps(ctx):
    vps_list = bot.db.get_user_vps(ctx.author.id)
    if not vps_list:
        return await ctx.send("📭 You don't have any VPS yet.", ephemeral=True)
    embed = discord.Embed(title="💻 Your EagleNode VPS", color=discord.Color.blue())
    for vps in vps_list:
        embed.add_field(
            name=f"{vps['vps_id']}",
            value=f"Status: {vps['status']}\nMemory: {vps['memory']} GB\nCPU: {vps['cpu']} cores\nDisk: {vps['disk']} GB",
            inline=False,
        )
    await ctx.send(embed=embed, ephemeral=True)

# ------------------------------------------------------------
# /vps_list  –  admin view of all VPS
# ------------------------------------------------------------
@bot.hybrid_command(name="vps_list", description="List all VPS instances (Admin only)")
async def vps_list(ctx):
    if not has_admin_role(ctx):
        return await ctx.send("❌ Admins only", ephemeral=True)
    all_vps = bot.db.get_all_vps()
    if not all_vps:
        return await ctx.send("No VPS found.", ephemeral=True)
    embed = discord.Embed(title="🗂️ All EagleNode VPS", color=discord.Color.blue())
    for token, vps in all_vps.items():
        embed.add_field(
            name=f"{vps['vps_id']}",
            value=f"Owner: <@{vps['created_by']}>\nStatus: {vps['status']}\nCPU: {vps['cpu']} cores / {vps['memory']} GB",
            inline=False,
        )
    await ctx.send(embed=embed, ephemeral=True)

# ------------------------------------------------------------
# /delete_vps  –  admin delete
# ------------------------------------------------------------
@bot.hybrid_command(name="delete_vps", description="Delete a VPS (Admin only)")
@app_commands.describe(vps_id="VPS ID to delete")
async def delete_vps(ctx, vps_id:str):
    if not has_admin_role(ctx):
        return await ctx.send("❌ Admins only", ephemeral=True)
    token, vps = bot.db.get_vps_by_id(vps_id)
    if not vps:
        return await ctx.send("❌ VPS not found", ephemeral=True)
    try:
        if bot.docker_client:
            cont = bot.docker_client.containers.get(vps["container_id"])
            cont.stop(timeout=5)
            cont.remove()
    except Exception as e:
        logger.warning(f"Container removal issue: {e}")
    bot.db.remove_vps(token)
    await ctx.send(f"🗑️ VPS {vps_id} deleted.", ephemeral=True)

# ------------------------------------------------------------
# /change_ssh_password
# ------------------------------------------------------------
@bot.hybrid_command(name="change_ssh_password", description="Change SSH password for a VPS")
@app_commands.describe(vps_id="VPS ID")
async def change_pw(ctx, vps_id:str):
    token, vps = bot.db.get_vps_by_id(vps_id)
    if not vps or vps["created_by"] != str(ctx.author.id):
        return await ctx.send("❌ VPS not found or not yours.", ephemeral=True)
    new_pw = generate_ssh_password()
    try:
        cont = bot.docker_client.containers.get(vps["container_id"])
        ok, out = await run_docker_command(cont.id, ["bash","-c",f"echo '{vps['username']}:{new_pw}'|chpasswd"])
        if not ok:
            return await ctx.send(f"❌ Failed: {out}", ephemeral=True)
        bot.db.update_vps(token, {"password": new_pw})
        emb = discord.Embed(title=f"🔑 New SSH Password for {vps_id}", color=discord.Color.green())
        emb.add_field(name="Username", value=vps["username"], inline=True)
        emb.add_field(name="Password", value=f"||{new_pw}||", inline=False)
        await ctx.author.send(embed=emb)
        await ctx.send("✅ Password changed. Check your DMs.", ephemeral=True)
    except Exception as e:
        await ctx.send(f"❌ Error: {e}", ephemeral=True)

# ------------------------------------------------------------
# ManageVPS View (buttons)
# ------------------------------------------------------------
class ManageVPSView(ui.View):
    def __init__(self, token, vps, user_id):
        super().__init__(timeout=300)
        self.token, self.vps, self.user_id = token, vps, user_id

    async def interaction_check(self, inter:discord.Interaction):
        if str(inter.user.id)==self.vps["created_by"] or has_admin_role(inter):
            return True
        await inter.response.send_message("❌ Not authorized", ephemeral=True)
        return False

    @ui.button(label="Start", style=discord.ButtonStyle.green)
    async def start_btn(self, inter, btn):
        try:
            c = bot.docker_client.containers.get(self.vps["container_id"])
            c.start(); bot.db.update_vps(self.token,{"status":"running"})
            await inter.response.send_message("🟢 Started", ephemeral=True)
        except Exception as e:
            await inter.response.send_message(f"❌ {e}", ephemeral=True)

    @ui.button(label="Stop", style=discord.ButtonStyle.danger)
    async def stop_btn(self, inter, btn):
        try:
            c = bot.docker_client.containers.get(self.vps["container_id"])
            c.stop(); bot.db.update_vps(self.token,{"status":"stopped"})
            await inter.response.send_message("🔴 Stopped", ephemeral=True)
        except Exception as e:
            await inter.response.send_message(f"❌ {e}", ephemeral=True)

    @ui.button(label="Restart", style=discord.ButtonStyle.secondary)
    async def restart_btn(self, inter, btn):
        try:
            c = bot.docker_client.containers.get(self.vps["container_id"])
            c.restart(); bot.db.update_vps(self.token,{"status":"running"})
            await inter.response.send_message("🔁 Restarted", ephemeral=True)
        except Exception as e:
            await inter.response.send_message(f"❌ {e}", ephemeral=True)

    @ui.button(label="Info", style=discord.ButtonStyle.primary)
    async def info_btn(self, inter, btn):
        emb = discord.Embed(title=f"ℹ️ VPS {self.vps['vps_id']}", color=discord.Color.blue())
        emb.add_field(name="Owner", value=f"<@{self.vps['created_by']}>", inline=True)
        emb.add_field(name="Status", value=self.vps["status"], inline=True)
        emb.add_field(
            name="Resources",
            value=f"{self.vps['memory']} GB RAM | {self.vps['cpu']} cores | {self.vps['disk']} GB disk",
            inline=False)
        await inter.response.send_message(embed=emb, ephemeral=True)

    @ui.button(label="Delete (Admin)", style=discord.ButtonStyle.red)
    async def del_btn(self, inter, btn):
        if not has_admin_role(inter):
            return await inter.response.send_message("❌ Admins only", ephemeral=True)
        try:
            c = bot.docker_client.containers.get(self.vps["container_id"])
            c.stop(); c.remove()
        except Exception: pass
        bot.db.remove_vps(self.token)
        await inter.response.send_message("🗑️ VPS deleted.", ephemeral=True)

# ------------------------------------------------------------
# /manage_vps  –  show control panel
# ------------------------------------------------------------
@bot.hybrid_command(name="manage_vps", description="Manage your VPS (Start/Stop/Restart/Info)")
@app_commands.describe(vps_id="VPS ID")
async def manage_vps(ctx, vps_id:str):
    token, vps = bot.db.get_vps_by_id(vps_id)
    if not vps:
        return await ctx.send("❌ VPS not found", ephemeral=True)
    if str(ctx.author.id)!=vps["created_by"] and not has_admin_role(ctx):
        return await ctx.send("❌ Not authorized", ephemeral=True)
    view = ManageVPSView(token, vps, ctx.author.id)
    emb = discord.Embed(title=f"🖥️ Manage VPS {vps_id}", color=discord.Color.blue())
    emb.add_field(name="Status", value=vps["status"], inline=True)
    emb.add_field(name="Resources", value=f"{vps['memory']} GB | {vps['cpu']} cores | {vps['disk']} GB", inline=False)
    await ctx.send(embed=emb, view=view, ephemeral=True)

# ------------------------------------------------------------
#  Run the bot
# ------------------------------------------------------------
if __name__ == "__main__":
    if not TOKEN:
        logger.error("❌ DISCORD_TOKEN not set in .env file.")
    else:
        bot.run(TOKEN)                          
