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
import webbrowser # <--- 新增导入，用于打开Steam链接
from collections import Counter

from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options as mitmproxy_options
from mitmproxy import http
from mitmproxy import connection

# --- 全局配置 ---
TARGET_EXE_NAME = "SquadGame.exe"
TARGET_PID = None
PROXY_ADDRESS = "127.0.0.1:8080"
CONFIG_INI_FILENAME = "config.ini"
INTERNET_SETTINGS_PATH = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
MITMPROXY_CA_CERT_FILENAME = "mitmproxy-ca-cert.pem"
CERT_COMMON_NAME_SUBSTRING = "mitmproxy"
DEFAULT_REMOTE_CONFIG_URL = "https://clone.squad.icu/config.json"
APP_ICON_FILENAME = "app_icon.ico"
ALLOWED_HOST_REGEX = r"api\.epicgames\.dev"
AUTO_FILTER_THRESHOLD_VALUE = 3
GHOST_PLAYER_LOG_THRESHOLD = 4 # 阴兵日志输出阈值
SQUAD_STEAM_APP_ID = "393380" # Squad 的 Steam AppID

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
            print(f"[提权] 尝试: {script} {params}")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", script, params, None, 1)
            return True
        except Exception as e:
            print(f"[提权错误] {e}")
            messagebox.showerror("提权失败", f"无法以管理员权限重新启动。\n请手动右键以管理员身份运行。\n错误: {e}")
            return False
    return True

# --- Windows 代理操作函数 ---
def get_current_proxy_settings_gui():
    settings = {'ProxyEnable': 0, 'ProxyServer': '', 'ProxyOverride': ''}
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_READ)
        for name in ['ProxyEnable', 'ProxyServer', 'ProxyOverride']:
            try: settings[name], _ = winreg.QueryValueEx(key, name)
            except FileNotFoundError: pass
        winreg.CloseKey(key)
    except Exception as e: print(f"[代理检查错误] {e}")
    return settings

def set_windows_proxy_gui(enable, proxy_server_str="", proxy_override_str_list=None):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1 if enable else 0)
        if enable:
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, proxy_server_str)
            final_overrides = set(["<local>"]) # Always bypass local addresses
            if proxy_override_str_list:
                final_overrides.update(item.strip().lower() for item in proxy_override_str_list if item.strip())
            override_string = ";".join(sorted(list(final_overrides)))
            winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, override_string)
            print(f"[代理状态] Windows 全局代理已启用 ({proxy_server_str}), 例外: {override_string}")
        else:
            # When disabling, clear ProxyServer and ProxyOverride as well
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, "")
            winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, "<local>") # Default override when disabled
            print(f"[代理状态] Windows 全局代理已禁用")
        winreg.CloseKey(key)

        # Notify system of proxy changes
        internet_set_option = getattr(ctypes.windll.Wininet, "InternetSetOptionW", None)
        if internet_set_option:
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
            print("[代理状态] 已通知系统代理设置更改。")
        else: print("[代理状态警告] 未能加载 Wininet.InternetSetOptionW。")
    except Exception as e: print(f"[代理设置错误] {e}"); raise

# --- mitmproxy 插件 (PacketInterceptor) ---
class PacketInterceptor:
    def __init__(self, app_instance, auto_filter_threshold):
        self.app = app_instance
        # self.original_proxy_settings = None # No longer needed for restoration
        self.proxy_was_set_by_us = False # Still useful to know if we actively set it
        self.local_ini_filter_list = []
        self.remote_json_filter_list = []
        self.effective_filter_list = set()
        self.target_matchmaking_url_pattern = None
        self.processed_flow_ids_for_auto_filter = set()
        self.auto_filter_threshold = auto_filter_threshold

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_file_path = os.path.join(script_dir, CONFIG_INI_FILENAME)
        self.config_parser = configparser.ConfigParser()

        print(f"[CMD_PLUGIN_INIT] {self.__class__.__name__}: 初始化完成。阈值: {self.auto_filter_threshold}")
        self.app.log_to_gui(f"[插件状态] {self.__class__.__name__}: 初始化完成。")

    def _update_effective_filter_list(self):
        self.effective_filter_list = set(self.local_ini_filter_list) | set(self.remote_json_filter_list)
        print(f"[CMD_PLUGIN_EFFECTIVE_LIST] 生效过滤列表已更新: {list(self.effective_filter_list)}")
        self.app.display_effective_config_content()


    def read_config_file(self):
        print(f"[CMD_PLUGIN_CONFIG_READ] 尝试读取本地INI '{self.config_file_path}'...")
        self.app.log_to_gui(f"[配置检查] 正在读取本地配置 '{CONFIG_INI_FILENAME}'...")

        new_local_list = []
        config_found_and_parsed = False
        try:
            if not os.path.exists(self.config_file_path):
                print(f"[CMD_PLUGIN_CONFIG] 本地INI配置文件 '{self.config_file_path}' 未找到。")
                self.app.log_to_gui(f"[本地配置] '{CONFIG_INI_FILENAME}' 未找到，将使用空列表。")
            else:
                self.config_parser.clear()
                read_files = self.config_parser.read(self.config_file_path, encoding='utf-8')
                if not read_files:
                    print(f"[CMD_PLUGIN_ERROR] configparser未能成功读取或解析 '{self.config_file_path}'。")
                    self.app.log_to_gui(f"[本地配置错误] 未能读取或解析 '{self.config_file_path}'。")
                else:
                    config_found_and_parsed = True
                    if 'MatchmakingFilter' in self.config_parser and 'FilterOutAddresses' in self.config_parser['MatchmakingFilter']:
                        addresses_str = self.config_parser['MatchmakingFilter']['FilterOutAddresses'].strip()
                        if addresses_str:
                            new_local_list = [addr.strip() for addr in addresses_str.split(',') if addr.strip()]

            if str(new_local_list) != str(self.local_ini_filter_list) or not self.local_ini_filter_list and new_local_list :
                self.app.log_to_gui(f"[本地配置] 本地配置已成功加载，屏蔽列表如下：{new_local_list}")
                print(f"[CMD_PLUGIN_CONFIG] 本地INI过滤列表已加载/更新: {new_local_list}")
            self.local_ini_filter_list = new_local_list
            self._update_effective_filter_list()
            return config_found_and_parsed
        except Exception as e:
            print(f"[CMD_PLUGIN_ERROR] 读取INI失败: {e}")
            self.app.log_to_gui(f"[本地配置错误] 读取INI失败: {e}")
            return False

    def update_remote_config_list(self, remote_list: list):
        print(f"[CMD_PLUGIN_REMOTE_UPDATE] 正在用远程列表更新插件: {remote_list}")
        self.remote_json_filter_list = list(set(remote_list))
        self._update_effective_filter_list()
        self.app.log_to_gui(f"[远程配置] 远程配置已成功加载，屏蔽列表如下：{self.remote_json_filter_list}")


    def load(self, loader):
        self.read_config_file()
        self.target_matchmaking_url_pattern = re.compile(
            r"^https://api\.epicgames\.dev/matchmaking/v1/[a-fA-F0-9]{32}/filter$"
        )
        print(f"[CMD_PLUGIN_LOAD] {self.__class__.__name__}: load() 方法执行完毕。")
        self.app.log_to_gui(f"[插件状态] {self.__class__.__name__}: load() 方法执行完毕。")

    def running(self):
        print(f"[CMD_PLUGIN_RUNNING] {self.__class__.__name__}: 开始运行...")
        self.app.log_to_gui(f"[插件状态] {self.__class__.__name__}: 开始运行...")
        try:
            # When the interceptor starts, always set the proxy for this application's use.
            # The App.__init__ should have handled disabling any pre-existing system proxy.
            print(f"[CMD_PLUGIN_PROXY] 插件启动，正在设置系统代理为 {PROXY_ADDRESS}...")
            set_windows_proxy_gui(True, PROXY_ADDRESS, BYPASS_PROXY_DOMAINS)
            self.proxy_was_set_by_us = True # Mark that this interceptor instance set the proxy.
            self.app.log_to_gui(f"[代理状态] 系统代理已为本程序启用: {PROXY_ADDRESS}")

        except Exception as e:
            print(f"[CMD_PLUGIN_ERROR] 运行中设置代理出错: {e}")
            self.app.log_to_gui(f"[代理设置错误] 运行中设置代理出错: {e}")

        self.find_target_pid()
        print(f"[CMD_PLUGIN_RUNNING] {self.__class__.__name__}: running() 方法执行完毕。")


    def done(self):
        print(f"[CMD_PLUGIN_DONE] {self.__class__.__name__}: 正在关闭...")
        # Always forcibly disable the system proxy when the interceptor is done.
        print("[CMD_PLUGIN_PROXY] 强制禁用 Windows 全局代理...")
        try:
            set_windows_proxy_gui(False) # Force disable
            print("[CMD_PLUGIN_PROXY] 成功强制禁用全局代理。")
            self.app.log_to_gui("[服务状态] 已强制禁用系统代理。")
        except Exception as e:
            print(f"[CMD_PLUGIN_ERROR] 强制禁用全局代理失败: {e}")
            self.app.log_to_gui(f"[代理清理错误] 强制禁用全局代理失败: {e}")

        print(f"[CMD_PLUGIN_DONE] {self.__class__.__name__}: 已停止。")
        self.app.log_to_gui(f"[插件状态] {self.__class__.__name__}: 已停止。")


    def find_target_pid(self):
        global TARGET_PID
        found_pid = None
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == TARGET_EXE_NAME.lower():
                    found_pid = proc.info['pid']
                    break
        except psutil.Error as e:
            print(f"[CMD_PLUGIN_ERROR] 查找进程 '{TARGET_EXE_NAME}' 时出错: {e}")
            self.app.log_to_gui(f"[进程检查错误] 查找进程 '{TARGET_EXE_NAME}' 时出错: {e}")
            return False

        current_status_prefix = "状态: 已开启保护" if self.app.is_proxy_running else "状态: 未开启保护"

        if found_pid is not None:
            if found_pid != TARGET_PID:
                print(f"[CMD_PLUGIN_PID] 目标进程 '{TARGET_EXE_NAME}' 已找到 (PID: {found_pid})")
                self.app.log_to_gui(f"[进程检查] {TARGET_EXE_NAME} 已开启 (PID: {found_pid})")
            self.app.update_main_status_text(f"{current_status_prefix} (监控中: {TARGET_EXE_NAME} PID: {found_pid})")
            TARGET_PID = found_pid
            return True
        else:
            if TARGET_PID is not None:
                print(f"[CMD_PLUGIN_PID] 目标进程 '{TARGET_EXE_NAME}' (之前PID: {TARGET_PID}) 已关闭或未找到。")
                self.app.log_to_gui(f"[进程检查] {TARGET_EXE_NAME} 未开启或已关闭。")
            self.app.update_main_status_text(f"{current_status_prefix} (目标: {TARGET_EXE_NAME} 未找到)")
            TARGET_PID = None
            return False

    def client_connected(self, client: connection.Client):
        self.find_target_pid()

    def get_pid_from_client_connection(self, client_conn: connection.Client):
        try:
            client_ip, client_port = client_conn.peername
            if client_ip == "127.0.0.1" or client_ip == "::1": # Check if connection is from localhost
                for p_conn in psutil.net_connections(kind='tcp'):
                    # Ensure the connection is established and has a PID
                    if p_conn.status == psutil.CONN_ESTABLISHED and \
                       p_conn.laddr.port == client_port and \
                       p_conn.pid is not None:
                        # Check if the remote port of this connection matches our proxy's listening port
                        proxy_listening_port = client_conn.sockname[1] # Get the port mitmproxy is listening on for this client
                        if p_conn.raddr.port == proxy_listening_port: # This means p_conn.laddr is the actual client
                            return p_conn.pid
        except (psutil.AccessDenied, psutil.NoSuchProcess): pass # Ignore processes we can't access or that died
        except Exception: pass # Catch any other potential errors
        return None


    def process_flow(self, flow: http.HTTPFlow, direction: str):
        try:
            global TARGET_PID

            if not TARGET_PID: return # If target game is not running, do nothing
            # Check if the request is from the target game process
            pid_of_flow = self.get_pid_from_client_connection(flow.client_conn)
            if pid_of_flow != TARGET_PID: return # Not from our target game

            cmd_log_prefix = f"[CMD_FLOW][{TARGET_EXE_NAME}:{TARGET_PID}] " # For command line logging
            gui_log_prefix = f"[{TARGET_EXE_NAME}:{TARGET_PID}] " # For GUI logging


            if flow.request.scheme != "https": return # Only process HTTPS traffic

            # Check if the URL matches the Epic Games matchmaking filter endpoint
            is_target_url = bool(self.target_matchmaking_url_pattern and self.target_matchmaking_url_pattern.fullmatch(flow.request.pretty_url))

            if direction == "request":
                if is_target_url:
                    print(f"{cmd_log_prefix}匹配到请求: {flow.request.method} {flow.request.pretty_url}")
                    self.app.log_to_gui(f"{gui_log_prefix}侦测到服务器列表刷新请求。")


            elif direction == "response" and flow.response: # Process responses
                if is_target_url: # Only if it's the matchmaking filter response
                    print(f"{cmd_log_prefix}匹配到响应: {flow.response.status_code} from {flow.request.pretty_url}")
                    self.app.log_to_gui(f"{gui_log_prefix}匹配到响应: {flow.response.status_code} from {flow.request.pretty_url}")

                    # Get original response text
                    response_text_original = flow.response.get_text(strict=False)
                    if not response_text_original:
                        print(f"{cmd_log_prefix}  处理错误: 原始响应体为空。")
                        self.app.log_to_gui(f"{gui_log_prefix}  处理错误: 原始响应体为空。")
                        return

                    # Parse original JSON
                    try:
                        data_original = json.loads(response_text_original)
                        sessions_original = data_original.get("sessions", [])
                        if not isinstance(sessions_original, list):
                            print(f"{cmd_log_prefix}  处理错误: 原始响应中'sessions'非列表。")
                            self.app.log_to_gui(f"{gui_log_prefix}  处理错误: 原始响应中'sessions'非列表。")
                            return
                    except json.JSONDecodeError:
                        print(f"{cmd_log_prefix}  处理错误: 解析原始响应JSON失败。")
                        self.app.log_to_gui(f"{gui_log_prefix}  处理错误: 解析原始响应JSON失败。")
                        return
                    except Exception as e_parse_orig:
                        print(f"{cmd_log_prefix}  处理错误: 获取原始会话时出错: {e_parse_orig}")
                        self.app.log_to_gui(f"{gui_log_prefix}  处理错误: 获取原始会话时出错: {e_parse_orig}")
                        return

                    # --- Step A: Initial filter based on current effective_filter_list ---
                    sessions_after_initial_filter = []
                    removed_by_initial_filter_details = [] # Store {name: addr} for logging

                    if self.effective_filter_list: # Only filter if the list is not empty
                        for session_item in sessions_original:
                            attributes = session_item.get("attributes", {})
                            address_bound = attributes.get("ADDRESSBOUND_s")
                            server_name = attributes.get("SERVERNAME_s", "未知服务器名称") # Get server name for logging
                            if address_bound and address_bound in self.effective_filter_list:
                                removed_by_initial_filter_details.append({"name": server_name, "addr": address_bound})
                            else:
                                sessions_after_initial_filter.append(session_item)
                    else: # If no filter list, keep all original sessions
                        sessions_after_initial_filter = list(sessions_original) # Make a copy

                    # Log servers removed by initial filter
                    if removed_by_initial_filter_details:
                        for item in removed_by_initial_filter_details:
                            self.app.log_to_gui(f"{gui_log_prefix} [克隆保护] “{item['name']}” (指向: {item['addr']}) 已根据配置屏蔽。")
                        print(f"{cmd_log_prefix}  初步配置屏蔽了 {len(removed_by_initial_filter_details)} 个服务器。")
                    
                    print(f"{cmd_log_prefix}  初步过滤后剩余: {len(sessions_after_initial_filter)} 个服务器。")


                    # --- Step B: Analyze the initially filtered list to detect new clones ---
                    newly_detected_clones_for_current_filter = set() # Clones to filter in this specific response
                    temp_newly_detected_for_config = [] # Clones to potentially add to config.ini
                    address_to_server_name_map = {} # Map address_bound to server_name for logging

                    # Only perform auto-detection if this flow hasn't been processed for auto-filter before
                    if flow.id not in self.processed_flow_ids_for_auto_filter:
                        # Populate address_to_server_name_map from sessions_after_initial_filter
                        # This map will help retrieve server names for addresses identified as clones
                        for session_item_map_build in sessions_after_initial_filter:
                            attributes_map_build = session_item_map_build.get("attributes", {})
                            address_bound_map_build = attributes_map_build.get("ADDRESSBOUND_s")
                            server_name_map_build = attributes_map_build.get("SERVERNAME_s", "未知服务器名称")
                            if address_bound_map_build and address_bound_map_build not in address_to_server_name_map: # Store first encountered name
                                address_to_server_name_map[address_bound_map_build] = server_name_map_build

                        address_counts = Counter()
                        for session_item_for_analysis in sessions_after_initial_filter: # Analyze the list *after* initial filtering
                            attributes = session_item_for_analysis.get("attributes", {})
                            address_bound = attributes.get("ADDRESSBOUND_s")
                            if address_bound:
                                address_counts[address_bound] += 1

                        for addr, count in address_counts.items():
                            # Ensure the address is not a "0.0.0.0:" address
                            if addr and addr.startswith("0.0.0.0:"):
                                print(f"[CMD_AUTO_FILTER_SKIP] 跳过自动屏蔽无效地址: {addr}")
                                # self.app.log_to_gui(f"{gui_log_prefix} [自动检测跳过] 地址 {addr} 因无效而被跳过。") # Removed GUI log as per user request
                                continue # Skip this address

                            if count >= self.auto_filter_threshold and addr not in self.effective_filter_list: # Check against the *original* effective list
                                temp_newly_detected_for_config.append(addr)
                                newly_detected_clones_for_current_filter.add(addr) # Add to set for immediate filtering
                                # Log the auto-detected clone with its name
                                server_name_for_log = address_to_server_name_map.get(addr, "未知服务器名称")
                                self.app.log_to_gui(f"{gui_log_prefix} [克隆保护] 检测到 “{server_name_for_log}” 是克隆服，指向：{addr}，已屏蔽。")


                        if temp_newly_detected_for_config:
                            # This summary log can be kept or removed if individual logs are sufficient
                            # For now, let's keep it for CMD, but the GUI gets individual server name logs
                            print(f"[CMD_AUTO_FILTER] 自动检测到以下地址将被加入配置: {temp_newly_detected_for_config}")
                            self.app.log_to_gui(f"{gui_log_prefix} [自动配置] 以上自动检测到的服务器地址将被尝试添加到本地配置文件。")
                        else:
                            print(f"[CMD_AUTO_FILTER] 未在当前响应中自动检测到新的、需要添加的克隆服。")
                            # No need for a GUI log if nothing was auto-detected to be added to config
                            # self.app.log_to_gui(f"{gui_log_prefix} [自动检测] 未发现新的需要屏蔽的克隆服。")


                    # --- Step C: Immediately apply newly detected clones to the current response (second round of filtering) ---
                    sessions_after_second_filter = []
                    if newly_detected_clones_for_current_filter: # If new clones were detected for *this specific response*
                        for session_item in sessions_after_initial_filter: # Filter the list that was already initially filtered
                            attributes = session_item.get("attributes", {})
                            address_bound = attributes.get("ADDRESSBOUND_s")
                            if not (address_bound and address_bound in newly_detected_clones_for_current_filter):
                                sessions_after_second_filter.append(session_item)
                        print(f"{cmd_log_prefix}  即时自动过滤后剩余: {len(sessions_after_second_filter)} 个服务器。")
                    else: # If no new clones to filter *for this response*, use the result from the initial filter
                        sessions_after_second_filter = list(sessions_after_initial_filter)


                    # --- Step D: "Ghost Player" protection logic on the twice-filtered list ---
                    sessions_for_client_final = []
                    ghost_players_fixed_count = 0
                    for session_item in sessions_after_second_filter: # Iterate over the list after both filtering stages
                        modified_session_item = json.loads(json.dumps(session_item)) # Deep copy to modify
                        attributes = modified_session_item.get("attributes", {})
                        player_count_l = attributes.get("PLAYERCOUNT_l")
                        total_players = modified_session_item.get("totalPlayers")
                        server_name = attributes.get('SERVERNAME_s', 'N/A') # Get server name for logging

                        if player_count_l is not None and total_players is not None:
                            try:
                                player_count_l_int = int(player_count_l)
                                total_players_int = int(total_players)
                                if player_count_l_int != total_players_int:
                                    # Log only if difference is greater than threshold
                                    if abs(player_count_l_int - total_players_int) > GHOST_PLAYER_LOG_THRESHOLD:
                                        log_msg = f"[阴兵保护]检测到 {server_name} 存在阴兵，已修正，修正前 {player_count_l_int} 人，修正后 {total_players_int} 人"
                                        self.app.log_to_gui(f"{gui_log_prefix}{log_msg}")
                                        print(f"{cmd_log_prefix}{log_msg}")
                                    else: # Still fix, but don't log verbosely
                                        print(f"{cmd_log_prefix}[阴兵保护静默修正] {server_name}: {player_count_l_int} -> {total_players_int}")
                                    attributes["PLAYERCOUNT_l"] = total_players_int # Correct the player count
                                    ghost_players_fixed_count += 1 # Count all fixes
                            except ValueError:
                                print(f"{cmd_log_prefix}  阴兵保护警告: PLAYERCOUNT_l或totalPlayers格式错误 for server {server_name}")
                        sessions_for_client_final.append(modified_session_item) # Add (possibly modified) session

                    if ghost_players_fixed_count > 0:
                         self.app.log_to_gui(f"{gui_log_prefix} [阴兵保护] 共修正了 {ghost_players_fixed_count} 个服务器的玩家数量。")
                         print(f"{cmd_log_prefix} [阴兵保护] 共修正了 {ghost_players_fixed_count} 个服务器的玩家数量。")

                    # --- Step E: Set the final response to be sent to the client ---
                    final_data_to_send_to_client = data_original.copy() # Start with a copy of original structure
                    final_data_to_send_to_client["sessions"] = sessions_for_client_final # Replace sessions with the fully filtered list
                    final_data_to_send_to_client["count"] = len(sessions_for_client_final) # Update count
                    flow.response.text = json.dumps(final_data_to_send_to_client, ensure_ascii=False) # Set the modified text

                    # Logging the outcome
                    total_removed_overall = len(sessions_original) - len(sessions_for_client_final) # Calculate total removed
                    if total_removed_overall > 0:
                        # The individual server removal logs are now more specific. This summary is still useful.
                        self.app.log_to_gui(f"{gui_log_prefix} 本次刷新共屏蔽 {total_removed_overall} 个服务器。")
                        print(f"{cmd_log_prefix}  最终结果: 共屏蔽 {total_removed_overall} 个服务器。发送给客户端 {len(sessions_for_client_final)} 个。")
                    elif ghost_players_fixed_count > 0 : # If only ghost players were fixed, but no servers removed
                         self.app.log_to_gui(f"{gui_log_prefix} 响应已发送（仅修正阴兵，未屏蔽服务器）。")
                    else: # No servers removed, no ghost players fixed
                        self.app.log_to_gui(f"{gui_log_prefix} 响应已发送（未屏蔽服务器，未修正阴兵）。")
                        print(f"{cmd_log_prefix}  最终结果: 未屏蔽服务器，未修正阴兵。")


                    # --- Step F: Update local config.ini if new clones were detected and should be saved ---
                    if temp_newly_detected_for_config and flow.id not in self.processed_flow_ids_for_auto_filter:
                        # Schedule the config update to run on the main GUI thread
                        self.app.after(10, self.app.add_clones_to_config_and_reload, temp_newly_detected_for_config)
                        self.processed_flow_ids_for_auto_filter.add(flow.id) # Mark this flow as processed for auto-filter
        except Exception as e_outer:
            print(f"[CMD_ERROR][PacketInterceptor.process_flow] 外部捕获到异常: {e_outer}")
            traceback.print_exc(file=sys.stdout) # Print full traceback to CMD
            self.app.log_to_gui(f"[插件错误][process_flow] 发生错误: {e_outer}")


    def request(self, flow: http.HTTPFlow) -> None: self.process_flow(flow, "request")
    def response(self, flow: http.HTTPFlow) -> None: self.process_flow(flow, "response")

# --- GUI 应用部分 ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Squad克隆服屏蔽工具 — Squad.ICU出品")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.mitm_thread = None
        self.mitm_master = None
        self.interceptor_addon_instance = None
        self.is_proxy_running = False
        self.cert_gen_thread = None
        self.certificate_checked_on_startup = False
        self.certificate_installed_successfully = False
        self.app_should_close_after_proxy_stop = False
        self.current_remote_filter_list = []

        self.current_frame = None
        self.local_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_INI_FILENAME)


        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr
        print("[GUI_INIT] 标准输出/错误流将输出到CMD。")

        # Disable system proxy if it's on at startup
        self.disable_system_proxy_on_startup_if_needed()

        if self.is_mitmproxy_cert_installed_by_name():
            print("[GUI_INIT] 检测到mitmproxy CA证书已安装，加载主界面。")
            self.certificate_installed_successfully = True
            self.setup_main_ui()
            self.after(100, self.initial_config_load)
        else:
            print("[GUI_INIT] 未检测到mitmproxy CA证书，加载初始安装界面。")
            self.setup_initial_ui()

        self.certificate_checked_on_startup = True # Mark that initial check (if any) is done
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        # Admin check is now handled in if __name__ == "__main__" before App instantiation

    def disable_system_proxy_on_startup_if_needed(self):
        print("[APP_STARTUP_PROXY_CHECK] 启动时检查系统代理状态...")
        self.log_to_gui("[系统检查] 启动时检查代理设置...")
        try:
            current_settings = get_current_proxy_settings_gui()
            if current_settings.get('ProxyEnable', 0) == 1:
                print(f"[APP_STARTUP_PROXY_CHECK] 检测到系统代理已启用 (服务器: {current_settings.get('ProxyServer', 'N/A')})。正在禁用...")
                self.log_to_gui(f"[系统检查] 检测到代理已启用，正在禁用...")
                set_windows_proxy_gui(False) # Force disable
                self.log_to_gui("[系统检查] 系统代理已在启动时被禁用。")
                print("[APP_STARTUP_PROXY_CHECK] 系统代理已在启动时被禁用。")
            else:
                print("[APP_STARTUP_PROXY_CHECK] 系统代理当前未启用，无需操作。")
                self.log_to_gui("[系统检查] 系统代理当前未启用。")
        except Exception as e:
            error_msg = f"启动时检查或禁用系统代理失败: {e}"
            print(f"[APP_STARTUP_PROXY_ERROR] {error_msg}")
            self.log_to_gui(f"[系统检查错误] {error_msg}")


    def initial_config_load(self):
        print("[APP_INIT_CONFIG] 开始初始配置加载流程...")
        self.check_and_create_local_ini_if_not_exists()
        self.fetch_remote_config_and_update_plugin(silent=True) # This will use direct connection now
        if self.interceptor_addon_instance: # Should not be the case here yet
            self.interceptor_addon_instance.read_config_file()
            if self.current_remote_filter_list:
                 self.interceptor_addon_instance.update_remote_config_list(self.current_remote_filter_list)
        else: # Display combined config based on what's loaded in App directly
            self.display_effective_config_content()


    def is_mitmproxy_cert_installed_by_name(self) -> bool:
        # ... (保持不变) ...
        print("[CERT_CHECK] 正在检查系统中是否已安装mitmproxy CA证书...")
        if os.name != 'nt':
            print("[CERT_CHECK] 非Windows系统，跳过证书检查。假定未安装。")
            return False
        try:
            # Use CREATE_NO_WINDOW to prevent flashing a cmd window
            command = ["certutil", "-store", "Root"]
            process = subprocess.run(command, capture_output=True, text=True, check=False, encoding='oem', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)

            if process.returncode != 0:
                print(f"[CERT_CHECK_ERROR] certutil -store Root 命令执行失败，返回码: {process.returncode}")
                # self.log_to_gui(f"[证书检查错误] certutil -store Root 失败: {process.stderr.strip()}") # Might be too verbose
                return False # Assume not installed if command fails

            output_lower = process.stdout.lower()
            # More robust check for mitmproxy certificate by common name substring
            if CERT_COMMON_NAME_SUBSTRING.lower() in output_lower:
                 # Iterate through lines to find a more definitive match if needed
                 lines = process.stdout.splitlines()
                 for i, line in enumerate(lines):
                     line_lower = line.lower()
                     if CERT_COMMON_NAME_SUBSTRING.lower() in line_lower:
                         # Check context lines for "Issuer" or "Subject" to be more sure it's a CN
                         context_lines = lines[max(0, i-2):min(len(lines), i+3)] # Check a few lines around
                         for ctx_line in context_lines:
                             ctx_line_lower = ctx_line.lower()
                             if "issuer" in ctx_line_lower or "subject" in ctx_line_lower or \
                                "颁发者" in ctx_line_lower or "使用者" in ctx_line_lower: # Chinese localization
                                print(f"[CERT_CHECK] 在证书库中找到可能匹配 '{CERT_COMMON_NAME_SUBSTRING}' 的证书。")
                                return True
            
            print(f"[CERT_CHECK] 未在证书库中找到明确的 '{CERT_COMMON_NAME_SUBSTRING}' CA证书。")
            return False
        except FileNotFoundError:
            print("[CERT_CHECK_ERROR] 系统命令 'certutil.exe' 未找到。无法检查证书。")
            # self.log_to_gui("[证书检查错误] 系统命令 'certutil.exe' 未找到。")
            return False # Cannot check, assume not installed
        except Exception as e:
            print(f"[CERT_CHECK_ERROR] 检查证书时发生意外错误: {e}")
            traceback.print_exc(file=sys.stdout)
            # self.log_to_gui(f"[证书检查错误] 检查时发生错误: {e}")
            return False # On error, assume not installed

    def setup_initial_ui(self):
        # ... (保持不变) ...
        if self.current_frame:
            self.current_frame.destroy()
        self.geometry("600x400") # Adjusted for initial simple UI
        self.current_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.current_frame.pack(expand=True, fill="both", padx=20, pady=20)
        initial_label = ctk.CTkLabel(self.current_frame,
                                     text="欢迎使用 Squad克隆服屏蔽工具!\n\n程序需要CA证书以修改HTTPS流量。\n请先安装mitmproxy CA证书。",
                                     font=("Arial", 16), justify="center")
        initial_label.pack(pady=(50, 20))
        self.large_install_cert_button = ctk.CTkButton(self.current_frame, text="安装 CA 证书",
                                                       command=self.install_certificate_gui_flow, height=60, font=("Arial", 20, "bold"))
        self.large_install_cert_button.pack(pady=20, padx=50, ipady=10) # Make button larger
        self.initial_status_label = ctk.CTkLabel(self.current_frame, text="提示: 安装证书可能需要管理员权限。", text_color="gray", font=("Arial", 12))
        self.initial_status_label.pack(pady=(10,50))
        # if not self.certificate_checked_on_startup: self.check_admin_privileges_on_startup() # Handled in main

    def setup_main_ui(self):
        # ... (UI布局和日志精简如前一个版本) ...
        if self.current_frame:
            self.current_frame.destroy()
        self.geometry("800x600") # Restore main UI size

        self.current_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.current_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Top control bar (Start/Stop buttons, Status)
        self.top_control_frame = ctk.CTkFrame(self.current_frame)
        self.top_control_frame.pack(pady=(0,5), padx=0, fill="x")

        self.start_button = ctk.CTkButton(self.top_control_frame, text="启动保护功能", command=self.start_proxy_thread, width=120) # Fixed width
        self.start_button.pack(side="left", padx=(0,5))
        self.stop_button = ctk.CTkButton(self.top_control_frame, text="停止保护功能", command=self.stop_proxy_thread_with_confirm, state="disabled", width=120) # Fixed width
        self.stop_button.pack(side="left", padx=5)
        self.status_label = ctk.CTkLabel(self.top_control_frame, text="状态: 未开启保护", width=200, anchor="w") # Give it some width
        self.status_label.pack(side="left", padx=(10,0), fill="x", expand=True) # Allow status to expand

        # Configuration display area
        self.config_display_outer_frame = ctk.CTkFrame(self.current_frame)
        self.config_display_outer_frame.pack(pady=5, padx=0, fill="x") # Allow x-fill for the outer frame

        self.config_header_frame = ctk.CTkFrame(self.config_display_outer_frame, fg_color="transparent")
        self.config_header_frame.pack(fill="x", padx=0, pady=(0,2))

        self.config_label = ctk.CTkLabel(self.config_header_frame, text="当前生效屏蔽配置 (合并远程与本地):", anchor="w") # Anchor west
        self.config_label.pack(side="left", padx=(0,5))

        self.update_config_button = ctk.CTkButton(self.config_header_frame, text="刷新远程配置", command=lambda: self.fetch_remote_config_and_update_plugin(silent=False), width=100) # Fixed width
        self.update_config_button.pack(side="right", padx=(0,0)) # Keep to the right

        self.config_display_textbox = ctk.CTkTextbox(self.config_display_outer_frame, wrap="word", height=100, font=("Consolas", 10), state="disabled") # Monospaced font
        self.config_display_textbox.pack(pady=(0,5), padx=0, fill="both", expand=True)

        # Log area
        self.log_label = ctk.CTkLabel(self.current_frame, text="运行日志:", anchor="w")
        self.log_label.pack(pady=(5,2), padx=0, fill="x")
        self.log_textbox = ctk.CTkTextbox(self.current_frame, wrap="word", height=150, font=("Consolas", 11)) # Monospaced font
        self.log_textbox.pack(pady=(0,10), padx=0, fill="both", expand=True)
        self.log_textbox.configure(state="disabled") # Read-only

        print("[GUI_MAIN_UI] 主界面已设置。")
        self.log_to_gui("[GUI] 主操作界面已加载。")
        if self.certificate_installed_successfully:
            self.log_to_gui("[GUI] CA证书已安装。")
        self.update_main_status_text("状态: 未开启保护") # Initial status
        # self.check_and_create_local_ini_if_not_exists() # Moved to initial_config_load
        # self.display_local_config_content() # Now display_effective_config_content
        # if not self.certificate_checked_on_startup: self.check_admin_privileges_on_startup() # Handled in main

    def fetch_remote_config_and_update_plugin(self, silent=False):
        """从远程URL下载配置，并更新插件的远程过滤列表"""
        print("[CMD_CONFIG_UPDATE] 尝试从远程获取配置...")
        if not silent:
            self.log_to_gui("[配置更新] 正在从远程URL获取基础屏蔽列表...")

        remote_url = DEFAULT_REMOTE_CONFIG_URL
        if not silent:
            self.log_to_gui(f"[配置更新] 目标URL: {remote_url}")
        print(f"[CMD_CONFIG_UPDATE] 目标URL: {remote_url}")

        try:
            if not silent: self.update_main_status_text(f"状态: 正在下载远程配置...")
            self.log_to_gui(f"正在下载配置: {remote_url}...")
            
            # Ensure requests bypasses any system/script proxy for this specific call
            proxies = { "http": None, "https": None }
            response = requests.get(remote_url, timeout=10, proxies=proxies)
            response.raise_for_status()

            remote_data = response.json()
            print(f"[CMD_CONFIG_UPDATE] 从远程获取到的原始JSON数据: {remote_data}")

            filter_out_addresses_value = remote_data.get("FilterOutAddresses")

            if filter_out_addresses_value is None:
                log_msg = "[配置更新错误] 远程JSON中未找到 'FilterOutAddresses' 键。"
                self.log_to_gui(log_msg)
                print(f"[CMD_CONFIG_UPDATE_ERROR] {log_msg}")
                if not silent: messagebox.showerror("配置错误", "远程配置文件格式不正确：缺少 'FilterOutAddresses'。")
                if not silent: self.update_main_status_text("状态: 远程配置格式错误")
                return False

            downloaded_list = []
            if isinstance(filter_out_addresses_value, list):
                downloaded_list = [str(addr).strip() for addr in filter_out_addresses_value if str(addr).strip()]
            elif isinstance(filter_out_addresses_value, str): # Handle comma-separated string as well
                downloaded_list = [addr.strip() for addr in filter_out_addresses_value.split(',') if addr.strip()]
            else:
                log_msg = f"[配置更新错误] 远程JSON中 'FilterOutAddresses' 的值类型不受支持: {type(filter_out_addresses_value)}。"
                self.log_to_gui(log_msg)
                print(f"[CMD_CONFIG_UPDATE_ERROR] {log_msg}")
                if not silent: messagebox.showerror("配置错误", f"远程配置文件格式不正确：'FilterOutAddresses' 值类型错误。")
                if not silent: self.update_main_status_text("状态: 远程配置格式错误")
                return False

            self.current_remote_filter_list = downloaded_list # Cache it in the app
            if self.interceptor_addon_instance: # If proxy is running, update plugin directly
                self.interceptor_addon_instance.update_remote_config_list(downloaded_list)
            else: # If proxy not running, the plugin will pick it up when it starts
                print("[CMD_CONFIG_UPDATE] 插件实例尚不存在，远程配置已缓存。")
                self.display_effective_config_content() # Update GUI display if proxy not running

            if not silent:
                messagebox.showinfo("远程配置加载成功", f"已从远程加载 {len(downloaded_list)} 条基础屏蔽规则。")
                self.update_main_status_text("状态: 远程配置已应用")
            return True

        except requests.exceptions.RequestException as e:
            log_msg = f"[配置更新错误] 下载远程配置失败: {e}"
            self.log_to_gui(log_msg)
            print(f"[CMD_CONFIG_UPDATE_ERROR] {log_msg}")
            if not silent: messagebox.showerror("下载错误", f"无法从 {remote_url} 下载配置。\n错误: {e}")
            if not silent: self.update_main_status_text("状态: 远程配置下载失败")
        except json.JSONDecodeError: # If the response is not valid JSON
            log_msg = "[配置更新错误] 解析远程JSON配置失败。"
            self.log_to_gui(log_msg)
            print(f"[CMD_CONFIG_UPDATE_ERROR] {log_msg}")
            if not silent: messagebox.showerror("格式错误", "远程配置文件不是有效的JSON格式。")
            if not silent: self.update_main_status_text("状态: 远程配置格式错误")
        except Exception as e: # Catch any other unexpected errors
            log_msg = f"[配置更新错误] 更新配置时发生未知错误: {e}"
            self.log_to_gui(log_msg)
            print(f"[CMD_CONFIG_UPDATE_ERROR] {log_msg}")
            traceback.print_exc(file=sys.stdout)
            if not silent: messagebox.showerror("未知错误", f"更新配置时发生错误。\n详情请查看CMD窗口输出。")
            if not silent: self.update_main_status_text("状态: 配置更新时发生未知错误")
        return False


    def add_clones_to_config_and_reload(self, newly_detected_clones: list):
        if not newly_detected_clones:
            return

        print(f"[CMD_AUTO_CONFIG_UPDATE] 正在将 {newly_detected_clones} 添加到 {CONFIG_INI_FILENAME}...")
        self.log_to_gui(f"[自动屏蔽] 正在将新检测到的克隆服地址添加到本地配置: {newly_detected_clones}")

        config_editor = configparser.ConfigParser()
        current_addresses_str = ""

        try:
            if os.path.exists(self.local_config_path):
                config_editor.read(self.local_config_path, encoding='utf-8')
                if config_editor.has_section('MatchmakingFilter') and config_editor.has_option('MatchmakingFilter', 'FilterOutAddresses'):
                    current_addresses_str = config_editor.get('MatchmakingFilter', 'FilterOutAddresses')

            current_addresses_list = [addr.strip() for addr in current_addresses_str.split(',') if addr.strip()]

            updated_addresses_set = set(current_addresses_list)
            added_new_for_log = False
            for clone_addr in newly_detected_clones:
                if clone_addr not in updated_addresses_set: # Only add if not already present
                    updated_addresses_set.add(clone_addr)
                    added_new_for_log = True

            if not added_new_for_log: # If all detected clones were already in the list
                print(f"[CMD_AUTO_CONFIG_UPDATE] 所有新检测到的地址已存在于本地配置中。")
                self.log_to_gui(f"[自动屏蔽] 所有新检测到的地址已存在于本地配置中。")
                return # No need to rewrite or reload

            updated_addresses_str_to_write = ",".join(sorted(list(updated_addresses_set)))

            if not config_editor.has_section('MatchmakingFilter'):
                config_editor.add_section('MatchmakingFilter')

            config_editor.set('MatchmakingFilter', 'FilterOutAddresses', updated_addresses_str_to_write)

            with open(self.local_config_path, 'w', encoding='utf-8') as configfile:
                config_editor.write(configfile)

            self.log_to_gui(f"[自动屏蔽] 本地 {CONFIG_INI_FILENAME} 已更新。新列表: {list(updated_addresses_set)}")
            print(f"[CMD_AUTO_CONFIG_UPDATE] 本地 {CONFIG_INI_FILENAME} 已更新。")

            # self.display_local_config_content() # Now handled by read_config_file -> _update_effective_filter_list
            if self.interceptor_addon_instance: # If proxy is running, tell plugin to reload
                self.log_to_gui("[自动屏蔽] 正在通知插件重新加载本地配置...")
                print("[CMD_AUTO_CONFIG_UPDATE] 通知插件重新加载本地配置...")
                if self.interceptor_addon_instance.read_config_file(): # This will update effective_list and GUI
                     self.log_to_gui("[自动屏蔽] 插件已成功重新加载配置。")
                     print("[CMD_AUTO_CONFIG_UPDATE] 插件已重新加载配置。")
                else:
                     self.log_to_gui("[自动屏蔽错误] 插件重新加载本地配置时遇到问题。")
                     print("[CMD_AUTO_CONFIG_UPDATE_ERROR] 插件重新加载本地配置时遇到问题。")
            else: # If proxy not running, just update the GUI display directly
                self.log_to_gui("[自动屏蔽] 插件实例不存在，直接更新显示。")
                print("[CMD_AUTO_CONFIG_UPDATE_ERROR] 插件实例不存在，直接更新显示。")
                # Manually update local list cache in App and refresh display
                self.local_ini_filter_list = list(updated_addresses_set)
                self.display_effective_config_content()


        except IOError as e:
            self.log_to_gui(f"[自动屏蔽错误] 写入本地 {CONFIG_INI_FILENAME} 失败: {e}")
            print(f"[CMD_AUTO_CONFIG_UPDATE_ERROR] 写入本地 {CONFIG_INI_FILENAME} 失败: {e}")
        except Exception as e:
            self.log_to_gui(f"[自动屏蔽错误] 更新配置时发生未知错误: {e}")
            print(f"[CMD_AUTO_CONFIG_UPDATE_ERROR] 更新配置时发生未知错误: {e}")
            traceback.print_exc(file=sys.stdout)


    def display_effective_config_content(self): # Renamed from display_local_config_content
        """在GUI中显示当前生效的合并后屏蔽列表"""
        if hasattr(self, 'config_display_textbox') and self.config_display_textbox.winfo_exists():
            print(f"[CMD_DEBUG] 正在更新GUI中的生效配置显示...")

            effective_list_to_display = []
            if self.interceptor_addon_instance and self.interceptor_addon_instance.effective_filter_list:
                # If plugin is active, use its combined list
                effective_list_to_display = sorted(list(self.interceptor_addon_instance.effective_filter_list))
            else:
                # If plugin not active, combine App's cached remote list and freshly read local list
                local_list_temp = self._read_local_ini_for_display_only()
                effective_list_to_display = sorted(list(set(self.current_remote_filter_list) | set(local_list_temp)))


            content_to_display = ""
            if effective_list_to_display:
                # 日志点5 (部分): 将过滤列表 ['...']
                content_to_display = f"# 当前生效的屏蔽服务器列表 (合并自远程和本地 {CONFIG_INI_FILENAME})\n"
                content_to_display += f"# 总计: {len(effective_list_to_display)} 条\n"
                content_to_display += "[MatchmakingFilter]\n" # Mimic INI section for clarity
                content_to_display += f"FilterOutAddresses = {','.join(effective_list_to_display)}"
            else:
                 content_to_display = f"<当前无生效的屏蔽规则 (远程和本地 {CONFIG_INI_FILENAME} 均为空或未加载)>"

            # (Optional: Displaying pure local INI content can be removed if too verbose)
            # content_to_display += f"\n\n---\n纯本地 '{CONFIG_INI_FILENAME}' 内容:\n"
            # if os.path.exists(self.local_config_path):
            #     try:
            #         with open(self.local_config_path, 'r', encoding='utf-8') as f:
            #             local_ini_raw_content = f.read()
            #         content_to_display += local_ini_raw_content if local_ini_raw_content.strip() else f"<本地 {CONFIG_INI_FILENAME} 为空>"
            #     except Exception as e:
            #         content_to_display += f"<读取本地 {CONFIG_INI_FILENAME} 错误: {e}>"
            # else:
            #     content_to_display += f"<本地 {CONFIG_INI_FILENAME} 文件未找到>"


            try:
                self.config_display_textbox.configure(state="normal")
                self.config_display_textbox.delete("1.0", tk.END)
                self.config_display_textbox.insert("1.0", content_to_display)
                self.config_display_textbox.configure(state="disabled")
                print(f"[CMD_DEBUG] 生效配置内容已更新到GUI。")
            except Exception as e:
                error_msg = f"显示生效配置失败: {e}"
                print(f"[CMD_ERROR] {error_msg}")
                self.log_to_gui(f"[配置显示错误] {error_msg}")
        else:
            print("[CMD_DEBUG] Config display textbox 不存在，无法更新。")

    def _read_local_ini_for_display_only(self) -> list:
        """仅为显示目的读取本地INI，不影响插件状态"""
        temp_parser = configparser.ConfigParser()
        local_list = []
        if os.path.exists(self.local_config_path):
            try:
                temp_parser.read(self.local_config_path, encoding='utf-8')
                if 'MatchmakingFilter' in temp_parser and 'FilterOutAddresses' in temp_parser['MatchmakingFilter']:
                    addresses_str = temp_parser['MatchmakingFilter']['FilterOutAddresses'].strip()
                    if addresses_str:
                        local_list = [addr.strip() for addr in addresses_str.split(',') if addr.strip()]
            except Exception as e:
                print(f"[CMD_DEBUG_ERROR] _read_local_ini_for_display_only 失败: {e}")
        return local_list


    def check_admin_privileges_on_startup(self): # This method might be redundant if check is done in __main__
        if not is_admin():
            warning_message = "警告: 非管理员权限，证书和代理设置可能失败。"
            # Update appropriate status label if UI is already partially set up
            if hasattr(self, 'initial_status_label') and self.initial_status_label.winfo_exists():
                self.initial_status_label.configure(text=warning_message)
            elif hasattr(self, 'status_label') and self.status_label.winfo_exists(): # For main UI
                self.log_to_gui(warning_message) # Log to main log box
                self.update_main_status_text("状态: 未开启保护 (非管理员)")
            else: print(warning_message) # Fallback to console if GUI not ready
            print("[CMD_WARNING] 程序未以管理员身份运行。")


    def _get_mitmproxy_cert_path(self):
        mitmproxy_dir = os.path.join(os.path.expanduser("~"), ".mitmproxy")
        return os.path.join(mitmproxy_dir, MITMPROXY_CA_CERT_FILENAME)

    def _run_mitmproxy_for_cert_generation(self):
        print("[CMD_CERT_GEN_THREAD] 证书生成线程已启动。")
        self.log_to_gui("[证书生成] 正在尝试启动临时mitmproxy实例以生成CA证书...")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        temp_master = None
        try:
            opts = mitmproxy_options.Options(listen_host="127.0.0.1", listen_port=0) # Listen on a random available port
            temp_master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            print("[CMD_CERT_GEN_THREAD] 临时DumpMaster已创建。")
            self.log_to_gui("[证书生成] 临时mitmproxy实例已创建。")

            async def run_with_timed_shutdown():
                run_task = loop.create_task(temp_master.run())
                try:
                    await asyncio.sleep(3) # Allow time for cert generation
                    print("[CMD_CERT_GEN_THREAD] 临时实例已运行3秒，请求关闭。")
                    self.log_to_gui("[证书生成] 临时实例已运行，请求关闭。")
                finally:
                    if not run_task.done(): temp_master.should_exit.set()
                    print("[CMD_CERT_GEN_THREAD] 临时mitmproxy实例运行结束或被中断。")

            loop.run_until_complete(run_with_timed_shutdown())

        except Exception as e:
            print(f"[CMD_CERT_GEN_ERROR] 运行临时mitmproxy实例时出错: {e}")
            self.log_to_gui(f"[证书生成错误] 运行临时mitmproxy实例时出错: {e}")
            traceback.print_exc(file=sys.stdout)
        finally:
            if loop and not loop.is_closed(): loop.close()
            print("[CMD_CERT_GEN_THREAD] 证书生成线程的事件循环已关闭。")
            self.log_to_gui("[证书生成] 临时mitmproxy实例已关闭。")


    def install_certificate_gui_flow(self):
        print("[CMD_DEBUG] 用户请求安装CA证书...")
        status_label_to_update = self.initial_status_label if hasattr(self, 'initial_status_label') and self.initial_status_label.winfo_exists() else self.status_label
        if status_label_to_update and status_label_to_update.winfo_exists():
            status_label_to_update.configure(text="状态: 正在处理证书安装请求...")
        self.log_to_gui("[证书操作] 用户请求安装CA证书...")


        if not is_admin(): # Double check, though main should handle it
            self.log_to_gui("[证书错误] 需要管理员权限才能安装系统级CA证书。")
            messagebox.showerror("权限错误", "安装系统级CA证书需要管理员权限。\n请以管理员身份重新运行此程序。")
            if status_label_to_update and status_label_to_update.winfo_exists():
                status_label_to_update.configure(text="状态: 错误 - 需要管理员权限")
            return

        cert_path = self._get_mitmproxy_cert_path()

        if not os.path.exists(cert_path):
            self.log_to_gui(f"[证书操作] CA证书文件未找到。正在尝试生成...")
            if status_label_to_update and status_label_to_update.winfo_exists():
                status_label_to_update.configure(text="状态: CA证书未找到，正在尝试生成...")

            # Determine which install button is active to update its state
            active_install_button = self.large_install_cert_button if hasattr(self, 'large_install_cert_button') and self.large_install_cert_button.winfo_exists() else self.install_cert_button_main # Assuming main UI might have one
            if active_install_button: active_install_button.configure(state="disabled", text="正在生成...")
            self.update_idletasks() # Ensure UI updates

            self.cert_gen_thread = threading.Thread(target=self._run_mitmproxy_for_cert_generation, daemon=True)
            self.cert_gen_thread.start()

            def wait_and_recheck():
                if self.cert_gen_thread and self.cert_gen_thread.is_alive():
                    self.after(100, wait_and_recheck) # Check again shortly
                    return

                # Restore button state after thread finishes
                if active_install_button: active_install_button.configure(state="normal", text="安装 CA 证书" if active_install_button is self.large_install_cert_button else "检查/重装证书")

                self.log_to_gui("[证书操作] 证书生成尝试已完成。重新检查证书文件...")
                if status_label_to_update and status_label_to_update.winfo_exists():
                     status_label_to_update.configure(text="状态: 证书生成尝试完毕，检查文件中...")

                if not os.path.exists(cert_path):
                    self.log_to_gui(f"[证书错误] 仍然未找到CA证书文件于: {cert_path}")
                    self.log_to_gui("           请尝试先手动点击“启动保护功能”按钮运行一次主代理服务，")
                    self.log_to_gui("           然后再尝试安装证书。")
                    if status_label_to_update and status_label_to_update.winfo_exists():
                        status_label_to_update.configure(text="状态: 错误 - 证书生成失败或未找到")
                    messagebox.showwarning("证书未找到", f"mitmproxy CA证书文件在尝试生成后仍未找到。\n\n请确保mitmproxy有权限写入用户目录，或尝试先启动一次主代理服务。")
                    return
                else:
                    self._execute_cert_install(cert_path) # Proceed with installation

            self.after(100, wait_and_recheck) # Start the checking loop
            return # Exit current flow, wait_and_recheck will handle the rest

        # If cert_path already exists
        self._execute_cert_install(cert_path)

    def _execute_cert_install(self, cert_path):
        status_label_to_update = self.initial_status_label if hasattr(self, 'initial_status_label') and self.initial_status_label.winfo_exists() else self.status_label

        self.log_to_gui(f"[证书操作] 找到CA证书: {cert_path}。正在尝试安装...")
        if status_label_to_update and status_label_to_update.winfo_exists():
            status_label_to_update.configure(text="状态: 找到证书，正在尝试安装...")

        try:
            command = ["certutil", "-addstore", "-f", "Root", cert_path]
            process = subprocess.run(command, capture_output=True, text=True, check=False,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)

            if process.returncode == 0:
                self.log_to_gui("[GUI] CA证书已安装。") # Log success
                if status_label_to_update and status_label_to_update.winfo_exists():
                     status_label_to_update.configure(text="状态: 证书安装成功！")

                messagebox.showinfo("证书安装成功", "mitmproxy CA证书已成功安装！\n您可能需要重启相关应用程序。\n即将加载主操作界面。")
                self.certificate_installed_successfully = True # Update flag

                # If this was called from the initial UI, switch to main UI
                if hasattr(self, 'large_install_cert_button') and self.large_install_cert_button.winfo_exists():
                    self.after(100, self.setup_main_ui) # Delay to allow messagebox to clear
            else:
                self.log_to_gui(f"[证书错误] CA证书安装失败。certutil 返回码: {process.returncode}")
                self.log_to_gui(f"           certutil 输出: {process.stdout.strip()} {process.stderr.strip()}")
                if status_label_to_update and status_label_to_update.winfo_exists():
                     status_label_to_update.configure(text="状态: 错误 - 证书安装失败")
                messagebox.showerror("证书安装失败", f"CA证书安装失败。\n\ncertutil 返回码: {process.returncode}\n请确保以管理员身份运行本程序，并检查CMD窗口的详细输出。")
        except FileNotFoundError:
            self.log_to_gui("[证书错误] 系统命令 'certutil.exe' 未找到。")
            if status_label_to_update and status_label_to_update.winfo_exists():
                 status_label_to_update.configure(text="状态: 错误 - certutil.exe 未找到")
            messagebox.showerror("命令未找到", "系统命令 'certutil.exe' 未找到。\n无法自动安装证书，请尝试手动安装。")
        except Exception as e:
            self.log_to_gui(f"[证书错误] 自动安装证书时发生意外错误: {e}")
            if status_label_to_update and status_label_to_update.winfo_exists():
                 status_label_to_update.configure(text="状态: 错误 - 安装时发生意外错误")
            messagebox.showerror("安装错误", f"自动安装证书时发生意外错误：\n{e}")


    def check_and_create_local_ini_if_not_exists(self): # Creates a default config.ini if it's missing
        if not os.path.exists(self.local_config_path):
            log_msg = f"[配置] 本地 '{CONFIG_INI_FILENAME}' 未找到，正在创建默认文件..."
            self.log_to_gui(log_msg)
            print(f"[CMD_CONFIG] {log_msg}")
            try:
                default_config = configparser.ConfigParser()
                default_config.add_section('MatchmakingFilter')
                default_config.set('MatchmakingFilter', '# FilterOutAddresses: 使用英文逗号分隔多个 IP:端口 地址', None) # Comment
                default_config.set('MatchmakingFilter', 'FilterOutAddresses', '1.2.3.4:5555,127.0.0.1:7777') # Example entry
                with open(self.local_config_path, "w", encoding="utf-8") as f:
                    default_config.write(f)
                log_msg_created = f"[配置] 默认 '{CONFIG_INI_FILENAME}' 已创建。"
                self.log_to_gui(log_msg_created)
                print(f"[CMD_CONFIG] {log_msg_created}")
            except Exception as e:
                log_msg_error = f"[配置错误] 创建默认 {CONFIG_INI_FILENAME} 失败: {e}"
                self.log_to_gui(log_msg_error)
                print(f"[CMD_CONFIG_ERROR] {log_msg_error}")

    def log_to_gui(self, message): # Logs messages to the GUI textbox
        if hasattr(self, 'log_textbox') and self.log_textbox and self.log_textbox.winfo_exists(): # Check if textbox exists
            def _update(): # Schedule update in main GUI thread
                if self.log_textbox.winfo_exists(): # Double check before updating
                    self.log_textbox.configure(state="normal") # Enable editing
                    self.log_textbox.insert(tk.END, str(message) + "\n")
                    self.log_textbox.see(tk.END) # Scroll to the end
                    self.log_textbox.configure(state="disabled") # Disable editing
            self.log_textbox.after(0, _update) # Use after(0,...) for thread-safe GUI updates
        else: # Fallback if GUI textbox isn't ready
            print(f"[GUI_LOG_FALLBACK] {message}")


    def update_main_status_text(self, status_text: str): # Updates the main status label in the GUI
        target_label = None
        # Determine which status label is currently active
        if hasattr(self, 'status_label') and self.status_label and self.status_label.winfo_exists():
            target_label = self.status_label
        elif hasattr(self, 'initial_status_label') and self.initial_status_label and self.initial_status_label.winfo_exists(): # For initial UI
            target_label = self.initial_status_label

        if target_label:
            def _update(): # Schedule update in main GUI thread
                if target_label.winfo_exists(): # Check if label still exists
                    target_label.configure(text=status_text)
            target_label.after(0, _update) # Thread-safe update


    def mitmproxy_runner(self):
        print("[CMD_THREAD] mitmproxy_runner 线程已启动。")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        print(f"[CMD_THREAD] 已为线程 {threading.get_ident()} 创建并设置新的 asyncio 事件循环。")

        try:
            print("[CMD_THREAD] 正在创建 PacketInterceptor 插件实例...")
            self.interceptor_addon_instance = PacketInterceptor(self, AUTO_FILTER_THRESHOLD_VALUE)
            print("[CMD_THREAD] PacketInterceptor 实例已创建。")

            # If remote config was fetched before proxy started, apply it now
            if self.current_remote_filter_list:
                print(f"[CMD_THREAD] 将App中缓存的远程配置应用到新插件实例: {self.current_remote_filter_list}")
                self.interceptor_addon_instance.update_remote_config_list(self.current_remote_filter_list)

            self.interceptor_addon_instance.read_config_file() # Load local config into plugin


            print("[CMD_THREAD] 正在创建 mitmproxy 选项...")
            opts = mitmproxy_options.Options(
                listen_host="0.0.0.0", # Listen on all interfaces for the local proxy
                listen_port=int(PROXY_ADDRESS.split(':')[1]),
                allow_hosts=[ALLOWED_HOST_REGEX] # Only intercept traffic to specified hosts
            )
            print(f"[CMD_THREAD] mitmproxy 选项已创建，allow_hosts: {opts.allow_hosts}")
            # self.log_to_gui(f"[代理核心] 配置为仅拦截域名: {ALLOWED_HOST_REGEX}") # Reduced verbosity


            print("[CMD_THREAD] 正在创建 DumpMaster...")
            self.mitm_master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            self.mitm_master.addons.add(self.interceptor_addon_instance) # Add our custom interceptor

            print("[CMD_THREAD] DumpMaster 实例已创建，并已添加插件。")

            # Update GUI state to reflect proxy is running
            self.is_proxy_running = True
            self.after(0, lambda: self.update_main_status_text("状态: 已开启保护")) # Thread-safe GUI update
            self.after(0, lambda: self.start_button.configure(state="disabled"))
            self.after(0, lambda: self.stop_button.configure(state="normal"))
            self.after(0, lambda: self.update_config_button.configure(state="disabled")) # Disable config refresh while proxy runs
            self.log_to_gui(f"[服务状态] 服务已在 {PROXY_ADDRESS} 端口启动。")


            print("[CMD_THREAD] 即将调用 loop.run_until_complete(self.mitm_master.run())... (此为阻塞操作)")
            loop.run_until_complete(self.mitm_master.run()) # This blocks until mitm_master stops

        except PermissionError: # Specific error for port binding without admin
            self.log_to_gui("[代理核心错误] 启动代理失败：权限不足。请以管理员身份运行本程序。")
            print("[CMD_ERROR] 启动代理失败：权限不足。")
        except OSError as e: # Catch OS-level errors like "address already in use"
            if "address already in use" in str(e).lower() or "10048" in str(e): # Specific port conflict error
                 self.log_to_gui(f"[代理核心错误] 启动代理失败：端口 {PROXY_ADDRESS.split(':')[1]} 已被占用。")
                 print(f"[CMD_ERROR] 启动代理失败：端口 {PROXY_ADDRESS.split(':')[1]} 已被占用。")
            else:
                self.log_to_gui(f"[代理核心错误] 启动代理时发生OS错误: {e}")
                print(f"[CMD_ERROR] 启动代理时发生OS错误: {e}")
        except Exception as e: # Catch-all for other mitmproxy or asyncio errors
            self.log_to_gui(f"[代理核心错误] 启动或运行mitmproxy时发生意外错误: {e}")
            print(f"[CMD_ERROR] 启动或运行mitmproxy时发生意外错误: {e}")
            traceback_str = traceback.format_exc() # Get full traceback
            self.log_to_gui(f"[代理核心错误] 详细追溯: {traceback_str}")
            print(f"[CMD_ERROR] 详细追溯: {traceback_str}")
        finally:
            print("[CMD_THREAD] mitmproxy_runner 线程的 finally 块执行。")

            # Clean up asyncio loop
            print("[CMD_THREAD] 正在关闭事件循环...")
            if loop and not loop.is_closed():
                # Cancel all running tasks in this loop
                tasks = [t for t in asyncio.all_tasks(loop=loop) if t is not asyncio.current_task(loop=loop)]
                if tasks:
                    for task in tasks:
                        if not task.done(): task.cancel() # Cancel pending tasks
                    try:
                        # Wait for tasks to be cancelled
                        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
                    except asyncio.CancelledError:
                        print("[CMD_THREAD_FINALLY] asyncio.gather 在关闭事件循环时被取消。")
                    except RuntimeError as e: # Handle cases where loop might already be closing
                        print(f"[CMD_THREAD_FINALLY] 关闭事件循环中的任务时出错: {e}")

                if loop.is_running(): # Ensure loop is stopped before closing
                    loop.call_soon_threadsafe(loop.stop) # Stop it from another thread if needed
                if not loop.is_closed(): # Close the loop
                    loop.close()
                    print("[CMD_THREAD] 事件循环已关闭。")
                else:
                    print("[CMD_THREAD] 事件循环先前已关闭。")

            # Reset proxy state and GUI elements
            self.is_proxy_running = False
            if hasattr(self, 'start_button') and self.start_button.winfo_exists():
                 self.after(0, lambda: self.start_button.configure(text="启动保护功能", state="normal"))
            if hasattr(self, 'stop_button') and self.stop_button.winfo_exists():
                self.after(0, lambda: self.stop_button.configure(text="停止保护功能", state="disabled"))
            if hasattr(self, 'update_config_button') and self.update_config_button.winfo_exists():
                self.after(0, lambda: self.update_config_button.configure(state="normal"))
            self.after(0, lambda: self.update_main_status_text("状态: 未开启保护"))
            self.mitm_master = None # Clear master instance
            self.interceptor_addon_instance = None # Clear addon instance
            print("[CMD_DEBUG] mitmproxy DumpMaster 已停止。")

            if self.app_should_close_after_proxy_stop:
                print("[CMD_THREAD] 检测到 app_should_close_after_proxy_stop 为 True，准备关闭应用。")
                self.after(100, self.destroy_app_safely) # Schedule app destruction


    def start_proxy_thread(self):
        if not is_admin(): # Ensure admin rights before starting proxy
            self.log_to_gui("[权限错误] 必须以管理员身份运行才能启动代理并修改系统设置。")
            print("[CMD_ERROR] 启动代理失败：需要管理员权限。")
            messagebox.showerror("权限错误", "启动代理和修改系统设置需要管理员权限。\n请以管理员身份重新运行此程序。")
            return

        if not self.certificate_installed_successfully: # Ensure certificate is installed
            # Re-check just in case it was installed manually after app start
            if self.is_mitmproxy_cert_installed_by_name():
                self.log_to_gui("[证书检查] 系统中已存在mitmproxy CA证书。")
                self.certificate_installed_successfully = True
            else:
                self.log_to_gui("[操作错误] 请先成功安装CA证书，然后再启动代理。")
                print("[CMD_ERROR] 尝试在未安装证书的情况下启动代理。")
                messagebox.showwarning("证书未安装", "检测到mitmproxy CA证书可能未安装或未被信任。\n请先点击“安装CA证书”按钮并成功安装证书后，再启动代理服务。")
                return

        if self.is_proxy_running or (self.mitm_thread and self.mitm_thread.is_alive()):
            self.log_to_gui("[操作] 代理已经在运行中。")
            print("[CMD_DEBUG] 代理已经在运行中，启动请求被忽略。")
            return

        self.log_to_gui("[服务状态] 正在启动克隆服屏蔽服务...")
        print("[CMD_DEBUG] 正在尝试启动代理服务线程...")
        self.app_should_close_after_proxy_stop = False # Reset flag
        self.mitm_thread = threading.Thread(target=self.mitmproxy_runner, daemon=True)
        self.mitm_thread.start()

    def stop_proxy_thread_with_confirm(self): # Handles user confirmation before stopping
        print("[CMD_DEBUG] stop_proxy_thread_with_confirm() 被调用。")
        if not self.is_proxy_running and not self.mitm_master: # If not running, do nothing
            self.log_to_gui("[操作] 保护功能未在运行中。")
            print("[CMD_DEBUG] 保护功能未在运行中，停止请求被忽略。")
            return

        user_confirmation = messagebox.askyesno(
            "确认停止保护",
            "由于技术因素，停止保护后您将无法正常游戏，所以停止后将为您关闭战术小队游戏客户端。\n\n您确定要停止保护功能吗？"
        )

        if user_confirmation:
            self.log_to_gui("[操作] 用户确认停止保护功能。")
            print("[CMD_DEBUG] 用户确认停止保护功能。")
            self.terminate_squadgame_process() # Close SquadGame.exe
            self.app_should_close_after_proxy_stop = True # Signal that app should close after proxy stops
            self.stop_proxy_thread() # Proceed to stop the proxy
        else:
            self.log_to_gui("[操作] 用户取消了停止保护功能的操作。")
            print("[CMD_DEBUG] 用户取消了停止保护功能的操作。")


    def stop_proxy_thread(self): # Actual logic to stop mitmproxy
        print(f"[CMD_DEBUG] stop_proxy_thread() 内部逻辑被调用。")

        if not self.is_proxy_running and not self.mitm_master : # If already stopped or not initialized
            print("[CMD_DEBUG] 代理未在运行中或 master 未初始化（内部），停止请求被忽略。")
            if self.app_should_close_after_proxy_stop: # If app was meant to close, do it now
                self.destroy_app_safely()
            return

        self.log_to_gui("[操作] 正在尝试停止保护功能...")
        print("[CMD_DEBUG] 正在尝试停止保护功能...")
        if self.mitm_master:
            try:
                # Check if mitm_master and its event loop are in a state that allows graceful shutdown
                if hasattr(self.mitm_master, 'should_exit') and self.mitm_master.event_loop and self.mitm_master.event_loop.is_running():
                    if self.mitm_master.should_exit.is_set(): # Already shutting down
                        print("[CMD_DEBUG] mitm_master 已经在关闭过程中。")
                    else:
                        # Safely signal mitmproxy to shut down from its own event loop
                        self.mitm_master.event_loop.call_soon_threadsafe(self.mitm_master.should_exit.set)
                        self.log_to_gui("[操作] 已请求 mitmproxy 关闭。")
                        print("[CMD_DEBUG] 已请求 mitmproxy 关闭 (通过 should_exit 事件)。")
                elif not (hasattr(self.mitm_master, 'should_exit') and self.mitm_master.event_loop and self.mitm_master.event_loop.is_running()):
                     # If mitm_master or loop is not in a runnable state, assume it's already stopped or crashed
                     print("[CMD_DEBUG] mitm_master 或其事件循环已不可用，可能已停止。")
                     self.is_proxy_running = False # Update state
                     # Reset GUI buttons
                     if hasattr(self, 'start_button') and self.start_button.winfo_exists():
                        self.start_button.configure(text="启动保护功能", state="normal")
                     if hasattr(self, 'stop_button') and self.stop_button.winfo_exists():
                        self.stop_button.configure(text="停止保护功能", state="disabled")
                     if hasattr(self, 'update_config_button') and self.update_config_button.winfo_exists():
                        self.update_config_button.configure(state="normal")
                     self.update_main_status_text("状态: 未开启保护 (可能已意外停止)")
                     if self.app_should_close_after_proxy_stop: # If app was meant to close
                         self.destroy_app_safely()

            except Exception as e:
                self.log_to_gui(f"[操作错误] 请求 mitmproxy 关闭时出错: {e}")
                print(f"[CMD_ERROR] 请求 mitmproxy 关闭时出错: {e}")
                traceback.print_exc(file=sys.stdout)
                if self.app_should_close_after_proxy_stop: # Ensure app closes even if error
                    self.destroy_app_safely()
        else: # mitm_master is None, shouldn't happen if is_proxy_running was true
            print("[CMD_DEBUG] self.mitm_master 为 None，无法停止。")
            self.is_proxy_running = False
            if hasattr(self, 'start_button') and self.start_button.winfo_exists():
                self.start_button.configure(text="启动保护功能", state="normal")
            if hasattr(self, 'stop_button') and self.stop_button.winfo_exists():
                self.stop_button.configure(text="停止保护功能", state="disabled")
            if hasattr(self, 'update_config_button') and self.update_config_button.winfo_exists():
                self.update_config_button.configure(state="normal")
            self.update_main_status_text("状态: 未开启保护 (Master丢失)")
            if self.app_should_close_after_proxy_stop: # Ensure app closes
                self.destroy_app_safely()


    def terminate_squadgame_process(self):
        print(f"[CMD_PROCESS] 正在尝试关闭 {TARGET_EXE_NAME}...")
        self.log_to_gui(f"[操作] 正在尝试关闭 {TARGET_EXE_NAME}...")
        terminated_count = 0
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == TARGET_EXE_NAME.lower():
                    try:
                        p = psutil.Process(proc.info['pid'])
                        p.terminate() # Send SIGTERM
                        p.wait(timeout=3) # Wait for graceful termination
                        print(f"[CMD_PROCESS] 已终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']})")
                        self.log_to_gui(f"[操作] 已终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']})")
                        terminated_count +=1
                    except psutil.NoSuchProcess: # Process already ended
                        print(f"[CMD_PROCESS] 进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 在尝试终止时已不存在。")
                        self.log_to_gui(f"[操作] 进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 在尝试终止时已不存在。")
                    except psutil.TimeoutExpired: # Process didn't terminate gracefully
                        print(f"[CMD_PROCESS_WARN] 终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 超时，尝试强制结束。")
                        self.log_to_gui(f"[操作警告] 终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 超时，尝试强制结束。")
                        p.kill() # Force kill
                        self.log_to_gui(f"[操作] 已强制结束进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']})")
                        terminated_count +=1
                    except Exception as e: # Other errors during termination
                        print(f"[CMD_PROCESS_ERROR] 终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 时发生错误: {e}")
                        self.log_to_gui(f"[操作错误] 终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 时发生错误: {e}")
            if terminated_count == 0:
                self.log_to_gui(f"[操作] 未找到正在运行的 {TARGET_EXE_NAME} 进程进行关闭。")
                print(f"[CMD_PROCESS] 未找到正在运行的 {TARGET_EXE_NAME} 进程。")

        except Exception as e: # Error during process iteration
            print(f"[CMD_PROCESS_ERROR] 遍历或终止进程时发生错误: {e}")
            self.log_to_gui(f"[操作错误] 遍历或终止进程时发生错误: {e}")

    def destroy_app_safely(self):
        print("[CMD_DEBUG] destroy_app_safely() 被调用。准备关闭GUI。")
        self.update_idletasks() # Process any pending GUI events
        # Restore original stdout/stderr if they were redirected (though not explicitly done in this script for GUI logs)
        if hasattr(self, '_original_stdout') and self._original_stdout is not None:
             sys.stdout = self._original_stdout
        if hasattr(self, '_original_stderr') and self._original_stderr is not None:
             sys.stderr = self._original_stderr
        self.destroy() # Destroy the Tkinter window


    def on_closing(self): # Handles the window close button [X]
        self.log_to_gui("[应用] 正在关闭应用程序...")
        print("[CMD_DEBUG] 正在关闭应用程序...")
        if self.is_proxy_running:
            self.log_to_gui("[应用] 正在停止保护功能...") # Log before messagebox
            print("[CMD_DEBUG] 正在停止保护功能...")

            user_confirmation = messagebox.askyesno(
                "确认关闭",
                "保护功能仍在运行。关闭程序前会尝试停止保护并关闭游戏客户端。\n\n您确定要关闭吗？"
            )
            if user_confirmation:
                self.terminate_squadgame_process() # Terminate game first
                self.app_should_close_after_proxy_stop = True # Set flag
                self.stop_proxy_thread() # Initiate proxy stop
                # The mitmproxy_runner's finally block will call destroy_app_safely
            else:
                self.log_to_gui("[应用] 用户取消了关闭操作。")
                print("[CMD_DEBUG] 用户取消了关闭操作。")
                return # Do not close
        else: # If proxy is not running, close directly
            self.destroy_app_safely()


if __name__ == "__main__":
    # import json # Already imported globally

    # Attempt to request admin rights on startup if not already admin (Windows only)
    if os.name == 'nt' and not is_admin():
        print("[MAIN] 检测到非管理员权限，尝试提权...")
        if run_as_admin(): # Attempt to re-launch with admin rights
            print("[MAIN] 提权请求已发送，原进程即将退出。如果UAC通过，新进程将以管理员身份启动。")
            sys.exit() # Exit the non-admin process
        else:
            # This part will likely not be reached if UAC is accepted,
            # but if run_as_admin fails or UAC is denied:
            print("[MAIN_ERROR] 提权失败或用户取消。程序可能无法正常工作。")
            # Show a simple Windows messagebox as Tkinter might not be ready
            ctypes.windll.user32.MessageBoxW(0, "程序需要管理员权限才能正常运行。\n请以管理员身份重新启动。", "权限不足", 0x10 | 0x0) # MB_ICONERROR | MB_OK
            sys.exit(1) # Exit if admin rights are not obtained

    # Set asyncio event loop policy for Windows if applicable (for mitmproxy)
    if sys.platform == "win32":
        try:
            if threading.current_thread() is threading.main_thread(): # Ensure this is the main thread
                if sys.version_info >= (3, 8) and os.name == 'nt': # Check Python version and OS
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                    print("[MAIN] 已尝试设置 Windows asyncio 事件循环策略。")
        except Exception as e:
            print(f"[MAIN_ERROR] 无法设置 WindowsSelectorEventLoopPolicy: {e}")

    app = App()
    print("[MAIN] App 实例已创建，即将进入 mainloop...")
    app.mainloop() # Start the Tkinter event loop
    print("[MAIN] App mainloop 已退出。")
