import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, simpledialog
import threading
import sys
import io
import asyncio
import os
import re
import configparser
import json
import psutil
import winreg
import traceback
import subprocess
import ctypes
import time
import requests
import webbrowser
from collections import Counter, defaultdict

from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options as mitmproxy_options
from mitmproxy import http
from mitmproxy import connection

# --- 全局配置 ---
TARGET_EXE_NAME = "SquadGame.exe"
TARGET_PID = None
PROXY_ADDRESS = "127.0.0.1:8080"
LOCAL_KEYWORD_FILENAME = "clone-keyword.ini"
REMOTE_KEYWORD_CONFIG_URL = "https://clone.squad.icu/keyword.ini"
INTERNET_SETTINGS_PATH = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
MITMPROXY_CA_CERT_FILENAME = "mitmproxy-ca-cert.pem"
CERT_COMMON_NAME_SUBSTRING = "mitmproxy"
APP_ICON_FILENAME = "app_icon.ico"
ALLOWED_HOST_REGEX = r"api\.epicgames\.dev"
CLONE_DETECTION_THRESHOLD = 3
GHOST_PLAYER_LOG_THRESHOLD = 4
ANTI_CLONE_KEYWORD = "anti-clone"

BYPASS_PROXY_DOMAINS = [
    "*.steampowered.com", "*.steamcommunity.com", "*.steamgames.com",
    "*.steamusercontent.com", "*.steamcontent.com", "*.steamnetwork.net",
    "*.akamaihd.net", "*.epicgames.com",
]

# --- 辅助函数：检查管理员权限 ---
def is_admin():
    if os.name == 'nt':
        try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except: return False
    return True

def run_as_admin():
    if os.name == 'nt':
        try:
            script = sys.executable if getattr(sys, 'frozen', False) else sys.executable
            params = " ".join(sys.argv) if getattr(sys, 'frozen', False) else f'"{os.path.abspath(__file__)}" {" ".join(sys.argv[1:])}'
            ctypes.windll.shell32.ShellExecuteW(None, "runas", script, params, None, 1)
            return True
        except Exception as e:
            messagebox.showerror("提权失败", f"无法以管理员权限重新启动。\n错误: {e}")
            return False
    return True

# --- Windows 代理操作函数 ---
def set_windows_proxy_gui(enable, proxy_server_str="", proxy_override_str_list=None):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1 if enable else 0)
        if enable:
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, proxy_server_str)
            final_overrides = set(["<local>"])
            if proxy_override_str_list:
                final_overrides.update(item.strip().lower() for item in proxy_override_str_list if item.strip())
            override_string = ";".join(sorted(list(final_overrides)))
            winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, override_string)
        else:
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, "")
            winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, "<local>")
        winreg.CloseKey(key)
        internet_set_option = getattr(ctypes.windll.Wininet, "InternetSetOptionW", None)
        if internet_set_option:
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        print(f"[代理设置错误] {e}")
        raise

# --- mitmproxy 插件 (PacketInterceptor) ---
class PacketInterceptor:
    def __init__(self, app_instance, local_keywords, remote_keywords):
        self.app = app_instance
        self.local_keyword_list = local_keywords
        self.remote_keyword_list = remote_keywords
        self.effective_keyword_list = set()
        self.target_matchmaking_url_pattern = None
        self._update_effective_keyword_list()

    def _update_effective_keyword_list(self):
        self.effective_keyword_list = {kw.lower() for kw in self.local_keyword_list} | {kw.lower() for kw in self.remote_keyword_list}

    def load(self, loader):
        self.target_matchmaking_url_pattern = re.compile(
            r"^https://api\.epicgames\.dev/matchmaking/v1/[a-fA-F0-9]{32}/filter$"
        )

    def running(self):
        try:
            set_windows_proxy_gui(True, PROXY_ADDRESS, BYPASS_PROXY_DOMAINS)
            self.app.log_to_gui(f"[代理状态] 系统代理已为本程序启用: {PROXY_ADDRESS}")
        except Exception as e:
            self.app.log_to_gui(f"[代理设置错误] {e}")

    def done(self):
        try:
            set_windows_proxy_gui(False)
            self.app.log_to_gui("[服务状态] 已强制禁用系统代理。")
        except Exception as e:
            self.app.log_to_gui(f"[代理清理错误] {e}")

    def find_target_pid(self):
        global TARGET_PID
        found_pid = None
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == TARGET_EXE_NAME.lower():
                    found_pid = proc.info['pid']
                    break
        except psutil.Error: pass
        
        current_status_prefix = "状态: 已开启保护" if self.app.is_proxy_running else "状态: 未开启保护"
        
        new_status_text = ""
        if found_pid is not None:
            new_status_text = f"{current_status_prefix} (监控中: {TARGET_EXE_NAME} PID: {found_pid})"
            if found_pid != TARGET_PID:
                self.app.log_to_gui(f"[进程检查] {TARGET_EXE_NAME} 已开启 (PID: {found_pid})")
        else:
            new_status_text = f"{current_status_prefix} (目标: {TARGET_EXE_NAME} 未找到)"
            if TARGET_PID is not None:
                self.app.log_to_gui(f"[进程检查] {TARGET_EXE_NAME} 未开启或已关闭。")

        if new_status_text != self.app.status_label.cget("text"):
             self.app.update_main_status_text(new_status_text)
        
        TARGET_PID = found_pid

    def get_pid_from_client_connection(self, client_conn: connection.Client):
        try:
            client_ip, client_port = client_conn.peername
            if client_ip == "127.0.0.1" or client_ip == "::1":
                for p_conn in psutil.net_connections(kind='tcp'):
                    if p_conn.status == psutil.CONN_ESTABLISHED and p_conn.laddr.port == client_port and p_conn.pid is not None:
                        if p_conn.raddr.port == client_conn.sockname[1]:
                            return p_conn.pid
        except (psutil.AccessDenied, psutil.NoSuchProcess, Exception): pass
        return None
        
    def process_flow(self, flow: http.HTTPFlow, direction: str):
        try:
            if not TARGET_PID or self.get_pid_from_client_connection(flow.client_conn) != TARGET_PID:
                return

            gui_log_prefix = f"[{TARGET_EXE_NAME}:{TARGET_PID}] "
            is_target_url = bool(self.target_matchmaking_url_pattern and self.target_matchmaking_url_pattern.fullmatch(flow.request.pretty_url))

            if direction == "request" and is_target_url:
                self.app.log_to_gui(f"{gui_log_prefix}侦测到服务器列表刷新请求。")
                try:
                    data = json.loads(flow.request.get_text(strict=False))
                    if data.get("maxResults") != 9999:
                        original_max_results = data.get("maxResults")
                        data["maxResults"] = 9999
                        flow.request.text = json.dumps(data)
                        self.app.log_to_gui(f"{gui_log_prefix}[请求修改] 已将 'maxResults' 从 {original_max_results} 修改为 9999。")
                except (json.JSONDecodeError, Exception) as e:
                    self.app.log_to_gui(f"{gui_log_prefix}[请求修改错误] {e}")

            elif direction == "response" and flow.response and is_target_url:
                data_original = json.loads(flow.response.get_text(strict=False))
                sessions_original = data_original.get("sessions", [])
                if not isinstance(sessions_original, list): return
                
                remaining_sessions = list(sessions_original)
                source_server_ips = set()
                if self.effective_keyword_list:
                    sessions_after_keyword_filter = []
                    for session in remaining_sessions:
                        server_name_lower = session.get("attributes", {}).get("SERVERNAME_s", "").lower()
                        original_server_name = session.get("attributes", {}).get("SERVERNAME_s", "Unknown Server")
                        is_blocked = False
                        for kw in self.effective_keyword_list:
                            if kw in server_name_lower:
                                ip = session.get("attributes", {}).get("ADDRESSBOUND_s")
                                if ip: source_server_ips.add(ip)
                                self.app.log_to_gui(f"{gui_log_prefix}[关键字屏蔽] “{original_server_name}” 已根据关键字规则屏蔽。")
                                is_blocked = True
                                break
                        if not is_blocked:
                            sessions_after_keyword_filter.append(session)
                    remaining_sessions = sessions_after_keyword_filter
                
                sessions_after_anticlone_filter = []
                anticlone_removed_count = 0
                for session in remaining_sessions:
                    search_keywords = session.get("attributes", {}).get("SEARCHKEYWORDS_s", "").lower()
                    if ANTI_CLONE_KEYWORD in search_keywords:
                        anticlone_removed_count += 1
                    else:
                        sessions_after_anticlone_filter.append(session)
                if anticlone_removed_count > 0:
                    self.app.log_to_gui(f"{gui_log_prefix}[特殊标志屏蔽] 过滤掉克里斯提供的警示服和反击服共 {anticlone_removed_count} 个。")
                remaining_sessions = sessions_after_anticlone_filter

                ip_counts = Counter(s.get("attributes", {}).get("ADDRESSBOUND_s") for s in remaining_sessions if s.get("attributes", {}).get("ADDRESSBOUND_s"))
                cloned_ips_info = {ip: [] for ip, count in ip_counts.items() if count >= CLONE_DETECTION_THRESHOLD}
                
                sessions_to_process_clones = []
                for session in remaining_sessions:
                    ip = session.get("attributes", {}).get("ADDRESSBOUND_s")
                    if ip in cloned_ips_info:
                        cloned_ips_info[ip].append(session)
                    else:
                        sessions_to_process_clones.append(session)
                
                sessions_to_keep = sessions_to_process_clones
                for ip, sessions_on_ip in cloned_ips_info.items():
                    if ip in source_server_ips:
                        server_name_sample = sessions_on_ip[0].get("attributes", {}).get("SERVERNAME_s", "未知")
                        self.app.log_to_gui(f"{gui_log_prefix}[源头克隆屏蔽] 检测到源头服 “{server_name_sample}” 正在克隆 (IP: {ip})，已全部屏蔽。")
                        continue
                    
                    names_on_ip = defaultdict(list)
                    for s in sessions_on_ip:
                        names_on_ip[s.get("attributes", {}).get("SERVERNAME_s")].append(s)
                    
                    for name, session_group in names_on_ip.items():
                        sessions_to_keep.append(session_group[0])
                remaining_sessions = sessions_to_keep

                # --- 【新功能】第四层过滤 (最终兜底 - 屏蔽所有重名服务器) ---
                final_name_counts = Counter(s.get("attributes", {}).get("SERVERNAME_s") for s in remaining_sessions)
                duplicate_names = {name for name, count in final_name_counts.items() if count > 1}
                
                if duplicate_names:
                    sessions_after_duplicate_filter = []
                    for session in remaining_sessions:
                        server_name = session.get("attributes", {}).get("SERVERNAME_s")
                        if server_name in duplicate_names:
                            self.app.log_to_gui(f"{gui_log_prefix}[重名屏蔽] “{server_name}” 因重名被屏蔽。")
                        else:
                            sessions_after_duplicate_filter.append(session)
                    remaining_sessions = sessions_after_duplicate_filter
                # --- 兜底过滤结束 ---
                
                final_sessions = []
                for session in remaining_sessions:
                    attributes = session.get("attributes", {})
                    player_count, total_players = attributes.get("PLAYERCOUNT_l"), session.get("totalPlayers")
                    if player_count is not None and total_players is not None:
                        try:
                            if int(player_count) != int(total_players):
                                session["attributes"]["PLAYERCOUNT_l"] = int(total_players)
                        except (ValueError, TypeError): pass
                    final_sessions.append(session)

                data_original["sessions"] = final_sessions
                data_original["count"] = len(final_sessions)
                
                final_json_text = json.dumps(data_original, ensure_ascii=False)
                flow.response.set_text(final_json_text)
                
        except (json.JSONDecodeError, Exception) as e:
            self.app.log_to_gui(f"[插件错误] 处理数据时发生错误: {e}")
            traceback.print_exc()

    def request(self, flow: http.HTTPFlow):
        self.process_flow(flow, "request")

    def response(self, flow: http.HTTPFlow):
        self.process_flow(flow, "response")

# --- GUI 应用部分 ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Squad克隆屏蔽工具V4 -Squad.ICU出品")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.mitm_thread = None
        self.mitm_master = None
        self.interceptor_addon_instance = None
        self.is_proxy_running = False
        self.certificate_installed_successfully = False
        self.app_should_close_after_proxy_stop = False
        self.current_remote_keyword_list = []
        self.current_local_keyword_list = []
        self.cert_gen_thread = None

        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(sys.executable)
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
        self.local_config_path = os.path.join(application_path, LOCAL_KEYWORD_FILENAME)

        self.disable_system_proxy_on_startup_if_needed()
        
        if self.is_mitmproxy_cert_installed_by_name():
            self.certificate_installed_successfully = True
            self.setup_main_ui()
            self.after(100, self.initial_config_load)
            self.after(1000, self.periodic_pid_check) 
        else:
            self.setup_initial_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def periodic_pid_check(self):
        if self.is_proxy_running and self.interceptor_addon_instance:
            self.interceptor_addon_instance.find_target_pid()
        self.after(3000, self.periodic_pid_check)

    def disable_system_proxy_on_startup_if_needed(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_READ)
            proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
            winreg.CloseKey(key)

            if proxy_enable == 1 and proxy_server == PROXY_ADDRESS:
                self.log_to_gui("[系统自愈] 检测到上次残留的代理设置，正在自动修复...")
                set_windows_proxy_gui(False)
                self.log_to_gui("[系统自愈] 代理已禁用，网络连接已恢复。")
        except FileNotFoundError:
            pass
        except Exception as e:
            self.log_to_gui(f"[系统检查错误] 无法检查或修复代理设置: {e}")

    def initial_config_load(self):
        self.check_and_create_local_ini_if_not_exists()
        self.read_and_update_local_keywords()
        self.fetch_remote_config_and_update_plugin(silent=True)
        self.display_effective_config_content()

    def is_mitmproxy_cert_installed_by_name(self) -> bool:
        if os.name != 'nt': return False
        try:
            command = ["certutil", "-store", "Root"]
            process = subprocess.run(command, capture_output=True, text=True, check=False, encoding='oem', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)
            return CERT_COMMON_NAME_SUBSTRING.lower() in process.stdout.lower() if process.returncode == 0 else False
        except (FileNotFoundError, Exception): return False

    def setup_initial_ui(self):
        self.geometry("600x400")
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(frame, text="欢迎使用 Squad克隆服屏蔽工具!\n\n程序需要CA证书以修改HTTPS流量。", font=("Arial", 16), justify="center").pack(pady=(50, 20))
        self.large_install_cert_button = ctk.CTkButton(frame, text="安装 CA 证书", command=self.install_certificate_gui_flow, height=60, font=("Arial", 20, "bold"))
        self.large_install_cert_button.pack(pady=20, padx=50, ipady=10)
        ctk.CTkLabel(frame, text="提示: 安装证书可能需要管理员权限。", text_color="gray", font=("Arial", 12)).pack(pady=(10,50))

    def setup_main_ui(self):
        self.geometry("800x600")
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        top_frame = ctk.CTkFrame(self.main_frame)
        top_frame.pack(pady=(0,5), padx=0, fill="x")
        self.start_button = ctk.CTkButton(top_frame, text="启动保护", command=self.start_proxy_thread, width=120)
        self.start_button.pack(side="left", padx=(0,5))
        self.stop_button = ctk.CTkButton(top_frame, text="停止保护", command=self.stop_proxy_thread_with_confirm, state="disabled", width=120)
        self.stop_button.pack(side="left", padx=5)
        self.status_label = ctk.CTkLabel(top_frame, text="状态: 未开启保护", width=200, anchor="w")
        self.status_label.pack(side="left", padx=(10,0), fill="x", expand=True)
        
        config_frame = ctk.CTkFrame(self.main_frame)
        config_frame.pack(pady=5, padx=0, fill="x")
        config_header = ctk.CTkFrame(config_frame, fg_color="transparent")
        config_header.pack(fill="x", padx=0, pady=(0,2))
        ctk.CTkLabel(config_header, text="当前生效屏蔽关键字 (合并远程与本地):", anchor="w").pack(side="left", padx=(0,5))
        self.update_config_button = ctk.CTkButton(config_header, text="刷新远程配置", command=lambda: self.fetch_remote_config_and_update_plugin(silent=False), width=100)
        self.update_config_button.pack(side="right", padx=(0,0))

        self.config_display_textbox = ctk.CTkTextbox(config_frame, wrap="word", height=100, font=("Consolas", 10), state="disabled")
        self.config_display_textbox.pack(pady=(0,5), padx=0, fill="both", expand=True)
        
        ctk.CTkLabel(self.main_frame, text="运行日志:", anchor="w").pack(pady=(5,2), padx=0, fill="x")
        self.log_textbox = ctk.CTkTextbox(self.main_frame, wrap="word", height=150, font=("Consolas", 11), state="disabled")
        self.log_textbox.pack(pady=(0,10), padx=0, fill="both", expand=True)
        self.log_to_gui("[GUI] 主操作界面已加载。")

    def read_and_update_local_keywords(self):
        self.log_to_gui(f"[配置检查] 正在读取本地配置 '{LOCAL_KEYWORD_FILENAME}'...")
        keywords = []
        try:
            if os.path.exists(self.local_config_path):
                parser = configparser.ConfigParser()
                parser.read(self.local_config_path, encoding='utf-8')
                if 'Keywords' in parser and 'Keywords' in parser['Keywords']:
                    keywords_str = parser['Keywords']['Keywords'].strip()
                    if keywords_str:
                        keywords = [kw.strip() for kw in keywords_str.split(',') if kw.strip()]
            self.current_local_keyword_list = keywords
            self.log_to_gui(f"[本地配置] 加载了 {len(keywords)} 个关键字。")
        except Exception as e:
            self.log_to_gui(f"[本地配置错误] 读取失败: {e}")
            self.current_local_keyword_list = []
    
    def fetch_remote_config_and_update_plugin(self, silent=False):
        if not silent: self.log_to_gui("[配置更新] 正在获取远程关键字...")
        try:
            if not silent: self.update_main_status_text("状态: 正在下载...")
            response = requests.get(REMOTE_KEYWORD_CONFIG_URL, timeout=10, proxies={"http": None, "https": None})
            response.raise_for_status()

            parser = configparser.ConfigParser()
            parser.read_string(response.text)
            
            keywords_str = parser.get('Keywords', 'Keywords', fallback='').strip()
            downloaded_list = [kw.strip() for kw in keywords_str.split(',') if kw.strip()]

            self.current_remote_keyword_list = downloaded_list
            self.display_effective_config_content() 
            if not silent:
                messagebox.showinfo("成功", f"已从远程加载 {len(downloaded_list)} 条关键字。")
        except Exception as e:
            self.log_to_gui(f"[配置更新错误] {e}")
            self.current_remote_keyword_list = []
            self.display_effective_config_content()
            if not silent: self.update_main_status_text("状态: 远程更新失败")

    def display_effective_config_content(self):
        if not hasattr(self, 'config_display_textbox') or not self.config_display_textbox.winfo_exists(): return
        
        effective_list = sorted(list(set(self.current_local_keyword_list) | set(self.current_remote_keyword_list)))
        
        content = f"# 当前生效屏蔽关键字: {len(effective_list)} 条\n[Keywords]\nKeywords = {','.join(effective_list)}"
        try:
            self.config_display_textbox.configure(state="normal")
            self.config_display_textbox.delete("1.0", tk.END)
            self.config_display_textbox.insert("1.0", content)
            self.config_display_textbox.configure(state="disabled")
        except tk.TclError: pass

    def _get_mitmproxy_cert_path(self):
        return os.path.join(os.path.expanduser("~"), ".mitmproxy", MITMPROXY_CA_CERT_FILENAME)

    def _run_mitmproxy_for_cert_generation(self):
        self.log_to_gui("[证书生成] 正在后台生成CA证书...")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            opts = mitmproxy_options.Options(listen_host="127.0.0.1", listen_port=0) 
            master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            
            async def run_with_timed_shutdown():
                run_task = loop.create_task(master.run())
                await asyncio.sleep(3)
                if not run_task.done(): master.should_exit.set()

            loop.run_until_complete(run_with_timed_shutdown())
        except Exception as e:
            self.log_to_gui(f"[证书生成错误] {e}")
        finally:
            if loop and not loop.is_closed():
                loop.close()
            self.log_to_gui("[证书生成] 后台任务完成。")

    def install_certificate_gui_flow(self):
        if not is_admin():
            messagebox.showerror("权限错误", "安装证书需要管理员权限。")
            return
        cert_path = self._get_mitmproxy_cert_path()
        if not os.path.exists(cert_path):
            self.log_to_gui("CA证书文件未找到。正在尝试生成...")
            self.large_install_cert_button.configure(state="disabled", text="正在生成...")
            self.update_idletasks()
            
            self.cert_gen_thread = threading.Thread(target=self._run_mitmproxy_for_cert_generation, daemon=True)
            self.cert_gen_thread.start()

            def wait_for_cert():
                if self.cert_gen_thread.is_alive():
                    self.after(100, wait_for_cert)
                    return
                
                self.large_install_cert_button.configure(state="normal", text="安装 CA 证书")
                
                if os.path.exists(cert_path):
                    self.log_to_gui("证书已成功生成。")
                    self._execute_cert_install(cert_path)
                else:
                    messagebox.showwarning("证书未找到", "证书生成失败。")

            self.after(100, wait_for_cert)
        else:
            self._execute_cert_install(cert_path)

    def _execute_cert_install(self, cert_path):
        try:
            command = ["certutil", "-addstore", "-f", "Root", cert_path]
            subprocess.run(command, check=True, creationflags=subprocess.CREATE_NO_WINDOW, capture_output=True)
            self.log_to_gui("CA证书已安装。")
            messagebox.showinfo("成功", "证书安装成功！")
            self.certificate_installed_successfully = True
            if hasattr(self, 'large_install_cert_button'):
                 self.large_install_cert_button.master.destroy()
            self.setup_main_ui()
            self.after(100, self.initial_config_load)
            self.after(1000, self.periodic_pid_check)
        except (subprocess.CalledProcessError, Exception) as e:
            messagebox.showerror("失败", f"证书安装失败: {e}")

    def check_and_create_local_ini_if_not_exists(self):
        if not os.path.exists(self.local_config_path):
            try:
                default_config = configparser.ConfigParser()
                default_config.add_section('Keywords')
                default_config.set('Keywords', '# Keywords: 使用英文逗号分隔多个关键字', None)
                default_config.set('Keywords', 'Keywords', '示例关键字1,示例关键字2')
                with open(self.local_config_path, "w", encoding="utf-8") as f: default_config.write(f)
            except IOError as e:
                self.log_to_gui(f"创建默认 {LOCAL_KEYWORD_FILENAME} 失败: {e}")

    def log_to_gui(self, message):
        if hasattr(self, 'log_textbox') and self.log_textbox.winfo_exists():
            self.after(0, lambda: self._update_log(message))

    def _update_log(self, message):
        if hasattr(self, 'log_textbox') and self.log_textbox.winfo_exists():
            try:
                self.log_textbox.configure(state="normal")
                self.log_textbox.insert(tk.END, str(message) + "\n")
                self.log_textbox.see(tk.END)
                self.log_textbox.configure(state="disabled")
            except tk.TclError:
                pass 

    def update_main_status_text(self, status_text: str):
        if hasattr(self, 'status_label') and self.status_label.winfo_exists():
            self.after(0, lambda: self.status_label.configure(text=status_text))

    def mitmproxy_runner(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self.interceptor_addon_instance = PacketInterceptor(
                self, 
                self.current_local_keyword_list, 
                self.current_remote_keyword_list
            )
            opts = mitmproxy_options.Options(listen_host="0.0.0.0", listen_port=int(PROXY_ADDRESS.split(':')[1]), allow_hosts=[ALLOWED_HOST_REGEX])
            self.mitm_master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            self.mitm_master.addons.add(self.interceptor_addon_instance)
            self.is_proxy_running = True
            self.after(0, self.update_gui_for_proxy_start)
            loop.run_until_complete(self.mitm_master.run())
        except Exception as e:
            self.log_to_gui(f"[代理核心错误] {e}")
        finally:
            if loop and not loop.is_closed(): loop.close()
            self.is_proxy_running = False
            self.after(0, self.update_gui_for_proxy_stop)
            if self.app_should_close_after_proxy_stop: self.after(100, self.destroy)

    def update_gui_for_proxy_start(self):
        self.update_main_status_text("状态: 已开启保护")
        if hasattr(self, 'start_button'): self.start_button.configure(state="disabled")
        if hasattr(self, 'stop_button'): self.stop_button.configure(state="normal")
        if hasattr(self, 'update_config_button'): self.update_config_button.configure(state="disabled")
    
    def update_gui_for_proxy_stop(self):
        self.update_main_status_text("状态: 未开启保护")
        if hasattr(self, 'start_button'): self.start_button.configure(state="normal")
        if hasattr(self, 'stop_button'): self.stop_button.configure(state="disabled")
        if hasattr(self, 'update_config_button'): self.update_config_button.configure(state="normal")

    def start_proxy_thread(self):
        if not is_admin() or not self.certificate_installed_successfully or self.is_proxy_running: return
        self.app_should_close_after_proxy_stop = False
        self.mitm_thread = threading.Thread(target=self.mitmproxy_runner, daemon=True)
        self.mitm_thread.start()

    def stop_proxy_thread_with_confirm(self):
        if not self.is_proxy_running: return
        if messagebox.askyesno("确认停止保护", "停止保护后将关闭游戏客户端。\n\n您确定要停止保护功能吗？"):
            self.terminate_squadgame_process()
            self.app_should_close_after_proxy_stop = True
            self.stop_proxy_thread()

    def stop_proxy_thread(self):
        if self.mitm_master and self.mitm_master.event_loop.is_running():
            self.mitm_master.event_loop.call_soon_threadsafe(self.mitm_master.should_exit.set)
        elif self.app_should_close_after_proxy_stop:
            self.destroy()

    def terminate_squadgame_process(self):
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == TARGET_EXE_NAME.lower():
                    psutil.Process(proc.info['pid']).terminate()
        except (psutil.Error, Exception): pass

    def on_closing(self):
        if self.is_proxy_running:
            if messagebox.askyesno("确认关闭", "保护仍在运行，关闭前会停止保护并关闭游戏。\n\n确定要关闭吗？"):
                self.terminate_squadgame_process()
                self.app_should_close_after_proxy_stop = True
                self.stop_proxy_thread()
        else:
            self.destroy()

if __name__ == "__main__":
    if os.name == 'nt' and not is_admin():
        if run_as_admin(): sys.exit()
        else:
            ctypes.windll.user32.MessageBoxW(0, "需要管理员权限才能运行。", "权限不足", 0x10)
            sys.exit(1)
    if sys.platform == "win32" and sys.version_info >= (3, 8):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception as e:
            print(f"无法设置事件循环策略: {e}")
    app = App()
    app.mainloop()
