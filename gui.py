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

# Steam 和其他常用域名，用于代理例外列表
BYPASS_PROXY_DOMAINS = [
    "*.steampowered.com",
    "*.steamcommunity.com",
    "*.steamgames.com",
    "*.steamusercontent.com",
    "*.steamcontent.com",
    "*.steamnetwork.net",
    "*.akamaihd.net", 
    "*.epicgames.com", 
]

# --- 辅助函数：检查管理员权限 ---
def is_admin():
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return True 

def run_as_admin():
    if os.name == 'nt':
        try:
            script = None
            params = " ".join(sys.argv[1:]) 
            if getattr(sys, 'frozen', False): 
                script = sys.executable 
                print(f"[提权] 尝试以管理员权限重新运行打包程序: {script} {params}")
            else: 
                script = sys.executable 
                params = f'"{os.path.abspath(__file__)}" {params}' 
                print(f"[提权] 尝试以管理员权限重新运行脚本: {script} {params}")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", script, params, None, 1)
            return True 
        except Exception as e:
            print(f"[提权错误] 尝试以管理员权限重新运行失败: {e}")
            messagebox.showerror("提权失败", f"无法以管理员权限重新启动程序。\n请手动右键点击程序并选择“以管理员身份运行”。\n错误: {e}")
            return False
    return True 

# --- Windows 代理操作函数 ---
def get_current_proxy_settings_gui():
    settings = {'ProxyEnable': 0, 'ProxyServer': '', 'ProxyOverride': ''}
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_READ)
        try: settings['ProxyEnable'], _ = winreg.QueryValueEx(key, 'ProxyEnable')
        except FileNotFoundError: pass
        try: settings['ProxyServer'], _ = winreg.QueryValueEx(key, 'ProxyServer')
        except FileNotFoundError: pass
        try: settings['ProxyOverride'], _ = winreg.QueryValueEx(key, 'ProxyOverride')
        except FileNotFoundError: pass
        winreg.CloseKey(key)
    except Exception as e:
        print(f"[代理检查错误] 读取原始代理设置失败: {e}") 
    return settings

def set_windows_proxy_gui(enable, proxy_server_str="", proxy_override_str_list=None):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1 if enable else 0)
        if enable:
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, proxy_server_str)
            
            final_overrides = set(["<local>"]) 
            if proxy_override_str_list:
                for item in proxy_override_str_list:
                    if item.strip(): 
                        final_overrides.add(item.strip().lower()) 
            override_string = ";".join(sorted(list(final_overrides)))
            
            winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, override_string)
            print(f"[代理状态] Windows 全局代理已启用 ({proxy_server_str}), 例外: {override_string}")
        else:
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, "") 
            winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, "") 
            print(f"[代理状态] Windows 全局代理已禁用")

        winreg.CloseKey(key)
        
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        internet_set_option = getattr(ctypes.windll.Wininet, "InternetSetOptionW", None)
        if internet_set_option:
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
            print("[代理状态] 已通知系统代理设置更改。")
        else:
            print("[代理状态警告] 未能加载 Wininet.InternetSetOptionW，某些应用可能不会立即感知代理变化。")

    except PermissionError:
        print("[代理设置错误] 设置 Windows 代理失败: 权限不足。")
        raise
    except Exception as e:
        print(f"[代理设置错误] 设置 Windows 代理时发生错误: {e}")
        raise

# --- mitmproxy 插件 (PacketInterceptor) ---
class PacketInterceptor:
    def __init__(self, app_instance): 
        self.app = app_instance 
        self.original_proxy_settings = None
        self.proxy_was_set_by_us = False
        self.filter_out_list = []
        self.target_matchmaking_url_pattern = None

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_file_path = os.path.join(script_dir, CONFIG_INI_FILENAME) 
        self.config_parser = configparser.ConfigParser()
        
        print(f"[CMD_PLUGIN_INIT] {self.__class__.__name__}: 初始化完成。")
        self.app.log_to_gui(f"[插件状态] {self.__class__.__name__}: 初始化完成。")

    def read_config_file(self):
        print(f"[CMD_PLUGIN_CONFIG_READ] {self.__class__.__name__}: 尝试读取配置文件 '{self.config_file_path}'...")
        self.app.log_to_gui(f"[配置检查] 正在读取本地配置 '{CONFIG_INI_FILENAME}'...") 
        previous_filter_list_str = str(self.filter_out_list) 
        
        config_found_and_parsed = False
        try:
            if not os.path.exists(self.config_file_path):
                print(f"[CMD_PLUGIN_CONFIG] 本地INI配置文件 '{self.config_file_path}' 未找到。")
                self.app.log_to_gui(f"[配置检查] 本地INI配置文件 '{self.config_file_path}' 未找到。过滤列表将清空。")
                self.filter_out_list = []
            else:
                self.config_parser.clear() 
                read_files = self.config_parser.read(self.config_file_path, encoding='utf-8')
                if not read_files: 
                    print(f"[CMD_PLUGIN_ERROR] configparser未能成功读取或解析 '{self.config_file_path}'。")
                    self.app.log_to_gui(f"[配置检查错误] 未能读取或解析 '{self.config_file_path}'。")
                else:
                    config_found_and_parsed = True
                    if 'MatchmakingFilter' in self.config_parser and 'FilterOutAddresses' in self.config_parser['MatchmakingFilter']:
                        addresses_str = self.config_parser['MatchmakingFilter']['FilterOutAddresses'].strip()
                        if addresses_str:
                            new_list = [addr.strip() for addr in addresses_str.split(',') if addr.strip()]
                            if str(new_list) != previous_filter_list_str or not self.filter_out_list: 
                                self.app.log_to_gui(f"[配置检查] 将过滤列表 {new_list}") 
                                print(f"[CMD_PLUGIN_CONFIG] 本地INI更新成功: 过滤列表 {new_list}")
                            self.filter_out_list = new_list
                        else: 
                            if self.filter_out_list: 
                                self.app.log_to_gui("[配置检查] INI中 FilterOutAddresses 为空，过滤列表已清空。")
                                print("[CMD_PLUGIN_CONFIG] INI中 FilterOutAddresses 为空，过滤列表已清空。")
                            self.filter_out_list = []
                    else: 
                        if self.filter_out_list: 
                             self.app.log_to_gui(f"[配置检查] INI中未找到配置，过滤列表已清空。")
                             print(f"[CMD_PLUGIN_CONFIG] INI中未找到配置，过滤列表已清空。")
                        self.filter_out_list = []
            
            self.app.display_local_config_content() 
            return config_found_and_parsed
        except Exception as e:
            print(f"[CMD_PLUGIN_ERROR] 读取INI失败: {e}")
            self.app.log_to_gui(f"[配置检查错误] 读取INI失败: {e}")
            return False


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
            self.original_proxy_settings = get_current_proxy_settings_gui()
            print(f"[CMD_PLUGIN_PROXY] 原始代理: Enable={self.original_proxy_settings.get('ProxyEnable',0)}, Server='{self.original_proxy_settings.get('ProxyServer','')}'")
            
            current_proxy_server = self.original_proxy_settings.get('ProxyServer', '')
            current_proxy_enabled = self.original_proxy_settings.get('ProxyEnable', 0)

            if current_proxy_enabled and current_proxy_server == PROXY_ADDRESS:
                print(f"[CMD_PLUGIN_PROXY] 系统代理已经是 {PROXY_ADDRESS}。")
                self.proxy_was_set_by_us = True 
            else:
                print(f"[CMD_PLUGIN_PROXY] 正在设置系统代理为 {PROXY_ADDRESS}...")
                set_windows_proxy_gui(True, PROXY_ADDRESS, BYPASS_PROXY_DOMAINS) 
                self.proxy_was_set_by_us = True
        except Exception as e:
            print(f"[CMD_PLUGIN_ERROR] 运行中设置代理出错: {e}")
            self.app.log_to_gui(f"[代理设置错误] 运行中设置代理出错: {e}")
        
        self.find_target_pid() 
        print(f"[CMD_PLUGIN_RUNNING] {self.__class__.__name__}: running() 方法执行完毕。")


    def done(self):
        print(f"[CMD_PLUGIN_DONE] {self.__class__.__name__}: 正在关闭...")
        if self.proxy_was_set_by_us and self.original_proxy_settings:
            print("[CMD_PLUGIN_PROXY] 尝试恢复原始的 Windows 代理设置...")
            try:
                original_override_list = self.original_proxy_settings.get('ProxyOverride', '').split(';')
                set_windows_proxy_gui( 
                    bool(self.original_proxy_settings.get('ProxyEnable', 0)),
                    self.original_proxy_settings.get('ProxyServer', ''),
                    original_override_list if any(s.strip() for s in original_override_list) else ['<local>'] 
                )
                print("[CMD_PLUGIN_PROXY] 成功恢复原始代理设置。")
                self.app.log_to_gui("[服务状态] 已清理系统代理设置。") 
            except Exception as e:
                print(f"[CMD_PLUGIN_ERROR] 恢复原始代理设置失败: {e}")
                self.app.log_to_gui(f"[代理恢复错误] 恢复原始代理设置失败: {e}")
        elif not self.proxy_was_set_by_us and self.original_proxy_settings:
             print("[CMD_PLUGIN_PROXY] 脚本启动时代理并非由本脚本设置，退出时不进行修改。")
             self.app.log_to_gui("[服务状态] 退出时未修改系统代理（非本程序设置）。") 
        else:
            print("[CMD_PLUGIN_PROXY] 未进行代理恢复操作。")
            self.app.log_to_gui("[服务状态] 退出时未进行代理恢复操作。") 
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
            if client_ip == "127.0.0.1" or client_ip == "::1":
                for p_conn in psutil.net_connections(kind='tcp'):
                    if p_conn.status == psutil.CONN_ESTABLISHED and \
                       p_conn.laddr.port == client_port and \
                       p_conn.pid is not None:
                        proxy_listening_port = client_conn.sockname[1] 
                        if p_conn.raddr.port == proxy_listening_port: 
                            return p_conn.pid
        except (psutil.AccessDenied, psutil.NoSuchProcess): pass
        except Exception: pass
        return None


    def process_flow(self, flow: http.HTTPFlow, direction: str):
        # import json # 移除此处的导入，依赖顶层导入
        try:
            global TARGET_PID
            
            if not TARGET_PID: return 
            pid_of_flow = self.get_pid_from_client_connection(flow.client_conn)
            if pid_of_flow != TARGET_PID: return 

            cmd_log_prefix = f"[CMD_FLOW][{TARGET_EXE_NAME}:{TARGET_PID}] " 
            
            if flow.request.scheme != "https": return

            is_target_url = bool(self.target_matchmaking_url_pattern and self.target_matchmaking_url_pattern.fullmatch(flow.request.pretty_url))

            if direction == "request":
                if is_target_url:
                    print(f"{cmd_log_prefix}匹配到请求: {flow.request.method} {flow.request.pretty_url}")
                    self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}] 侦测到服务器列表刷新请求。") 


            elif direction == "response" and flow.response:
                if is_target_url:
                    print(f"{cmd_log_prefix}匹配到响应: {flow.response.status_code} from {flow.request.pretty_url}")
                    
                    if not self.filter_out_list: 
                        print(f"{cmd_log_prefix}  替换结果: 过滤列表为空，未执行替换。")
                        self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}] 替换结果: 过滤列表为空，未执行替换。")
                        return

                    try:
                        content_type = flow.response.headers.get("content-type", "").lower()
                        if "application/json" not in content_type:
                            print(f"{cmd_log_prefix}  替换结果: 响应Content-Type非JSON ({content_type})，跳过。")
                            self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}] 替换结果: 响应Content-Type非JSON ({content_type})，跳过。")
                            return
                        
                        response_text = flow.response.get_text(strict=False)
                        if not response_text:
                            print(f"{cmd_log_prefix}  替换错误: 响应体为空。")
                            self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}] 替换错误: 响应体为空。")
                            return
                        data = json.loads(response_text) # 使用全局导入的 json

                        original_sessions = data.get("sessions", [])
                        if not isinstance(original_sessions, list):
                            print(f"{cmd_log_prefix}  替换结果: 响应中'sessions'非列表，跳过。")
                            self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}] 替换结果: 响应中'sessions'非列表，跳过。")
                            return

                        filtered_sessions = []
                        sessions_removed_count = 0
                        removed_server_details = [] 
                        for session_item in original_sessions: 
                            attributes = session_item.get("attributes", {})
                            address_bound = attributes.get("ADDRESSBOUND_s")
                            server_name = attributes.get('SERVERNAME_s', 'N/A')
                            
                            if address_bound and address_bound in self.filter_out_list:
                                sessions_removed_count += 1
                                removed_server_details.append(f"  移除: {address_bound} (名称: {server_name})")
                                print(f"{cmd_log_prefix}  移除服务器: {address_bound} (名称: {server_name})")
                            else:
                                filtered_sessions.append(session_item)
                        
                        if sessions_removed_count > 0:
                            data["sessions"] = filtered_sessions
                            data["count"] = len(filtered_sessions) 
                            flow.response.text = json.dumps(data, ensure_ascii=False) # 使用全局导入的 json
                            
                            for detail in removed_server_details:
                                self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}]{detail}")
                            
                            self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}] 已成功移除 {sessions_removed_count} 个克隆服务器(包括77服和目标服务器)。")
                            print(f"{cmd_log_prefix}  替换结果: 成功移除 {sessions_removed_count} 个服务器。新数量: {data['count']}。")
                        else:
                            print(f"{cmd_log_prefix}  替换结果: 未找到任何在列表 {self.filter_out_list} 中的服务器，响应未修改。")
                            self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}] 替换结果: 未找到任何在列表 {self.filter_out_list} 中的服务器，响应未修改。")

                    except json.JSONDecodeError: 
                        print(f"{cmd_log_prefix}  替换错误: 解析响应JSON失败。")
                        self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}] 替换错误: 解析响应JSON失败。部分原文: {flow.response.get_text(strict=False)[:100]}")
                    except Exception as e_inner: 
                        print(f"{cmd_log_prefix}  替换错误: 处理响应时发生未知错误: {e_inner}")
                        self.app.log_to_gui(f"[{TARGET_EXE_NAME}:{TARGET_PID}] 替换错误: 处理响应时发生未知错误: {e_inner}")
                        traceback.print_exc(file=sys.stdout) 
        except Exception as e_outer:
            print(f"[CMD_ERROR][PacketInterceptor.process_flow] 外部捕获到异常: {e_outer}")
            traceback.print_exc(file=sys.stdout) 
            self.app.log_to_gui(f"[插件错误][process_flow] 发生错误: {e_outer}")


    def request(self, flow: http.HTTPFlow) -> None: self.process_flow(flow, "request")
    def response(self, flow: http.HTTPFlow) -> None: self.process_flow(flow, "response")

# --- GUI 应用部分 ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Squad克隆服屏蔽工具 — 小米之家服务器专属") 
        ctk.set_appearance_mode("dark") 
        ctk.set_default_color_theme("blue")

        self.mitm_thread = None
        self.mitm_master = None
        self.interceptor_addon_instance = None 
        self.is_proxy_running = False
        self.cert_gen_thread = None
        self.certificate_checked_on_startup = False 
        self.certificate_installed_successfully = False 
        self.app_should_close_after_proxy_stop = False # 新增标志

        self.current_frame = None 
        self.local_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_INI_FILENAME)


        self._original_stdout = sys.stdout 
        self._original_stderr = sys.stderr 
        print("[GUI_INIT] 标准输出/错误流将输出到CMD。")

        if self.is_mitmproxy_cert_installed_by_name():
            print("[GUI_INIT] 检测到mitmproxy CA证书已安装，加载主界面。")
            self.certificate_installed_successfully = True 
            self.setup_main_ui()
        else:
            print("[GUI_INIT] 未检测到mitmproxy CA证书，加载初始安装界面。")
            self.setup_initial_ui()
        
        self.certificate_checked_on_startup = True
        self.protocol("WM_DELETE_WINDOW", self.on_closing) 
        # self.check_admin_privileges_on_startup() # 移到 if __name__ == "__main__" 中，在App实例化前检查

    def is_mitmproxy_cert_installed_by_name(self) -> bool:
        print("[CERT_CHECK] 正在检查系统中是否已安装mitmproxy CA证书...")
        if os.name != 'nt':
            print("[CERT_CHECK] 非Windows系统，跳过证书检查。假定未安装。")
            return False
        try:
            command = ["certutil", "-store", "Root"]
            process = subprocess.run(command, capture_output=True, text=True, check=False, encoding='oem', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)

            if process.returncode != 0:
                print(f"[CERT_CHECK_ERROR] certutil -store Root 命令执行失败，返回码: {process.returncode}")
                return False 

            output_lower = process.stdout.lower()
            if CERT_COMMON_NAME_SUBSTRING.lower() in output_lower:
                 lines = process.stdout.splitlines()
                 for i, line in enumerate(lines):
                     line_lower = line.lower()
                     if CERT_COMMON_NAME_SUBSTRING.lower() in line_lower:
                         context_lines = lines[max(0, i-2):min(len(lines), i+3)]
                         for ctx_line in context_lines:
                             ctx_line_lower = ctx_line.lower()
                             if "issuer" in ctx_line_lower or "subject" in ctx_line_lower or \
                                "颁发者" in ctx_line_lower or "使用者" in ctx_line_lower:
                                print(f"[CERT_CHECK] 在证书库中找到可能匹配 '{CERT_COMMON_NAME_SUBSTRING}' 的证书。")
                                return True
            
            print(f"[CERT_CHECK] 未在证书库中找到明确的 '{CERT_COMMON_NAME_SUBSTRING}' CA证书。")
            return False
        except FileNotFoundError:
            print("[CERT_CHECK_ERROR] 系统命令 'certutil.exe' 未找到。无法检查证书。")
            return False
        except Exception as e:
            print(f"[CERT_CHECK_ERROR] 检查证书时发生意外错误: {e}")
            traceback.print_exc(file=sys.stdout)
            return False

    def setup_initial_ui(self):
        if self.current_frame:
            self.current_frame.destroy()
        self.geometry("600x400") 
        self.current_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.current_frame.pack(expand=True, fill="both", padx=20, pady=20)
        initial_label = ctk.CTkLabel(self.current_frame, 
                                     text="欢迎使用 Squad克隆服屏蔽工具!\n\n程序需要CA证书以修改HTTPS流量。\n请先安装mitmproxy CA证书。",
                                     font=("Arial", 16), justify="center")
        initial_label.pack(pady=(50, 20))
        self.large_install_cert_button = ctk.CTkButton(self.current_frame, text="安装 CA 证书",
                                                       command=self.install_certificate_gui_flow, height=60, font=("Arial", 20, "bold"))
        self.large_install_cert_button.pack(pady=20, padx=50, ipady=10)
        self.initial_status_label = ctk.CTkLabel(self.current_frame, text="提示: 安装证书可能需要管理员权限。", text_color="gray", font=("Arial", 12))
        self.initial_status_label.pack(pady=(10,50))
        # if not self.certificate_checked_on_startup: self.check_admin_privileges_on_startup() # 由 main 块处理

    def setup_main_ui(self):
        if self.current_frame:
            self.current_frame.destroy()
        self.geometry("800x600") 

        self.current_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.current_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # --- 顶部控制框架 ---
        self.top_control_frame = ctk.CTkFrame(self.current_frame)
        self.top_control_frame.pack(pady=(0,5), padx=0, fill="x")

        self.start_button = ctk.CTkButton(self.top_control_frame, text="启动保护功能", command=self.start_proxy_thread, width=120) 
        self.start_button.pack(side="left", padx=(0,5))
        self.stop_button = ctk.CTkButton(self.top_control_frame, text="停止保护功能", command=self.stop_proxy_thread_with_confirm, state="disabled", width=120) 
        self.stop_button.pack(side="left", padx=5)
        self.status_label = ctk.CTkLabel(self.top_control_frame, text="状态: 未开启保护", width=200, anchor="w") 
        self.status_label.pack(side="left", padx=(10,0), fill="x", expand=True) 
        
        # --- 配置显示和更新框架 ---
        self.config_display_outer_frame = ctk.CTkFrame(self.current_frame)
        self.config_display_outer_frame.pack(pady=5, padx=0, fill="x")
        
        self.config_header_frame = ctk.CTkFrame(self.config_display_outer_frame, fg_color="transparent")
        self.config_header_frame.pack(fill="x", padx=0, pady=(0,2))

        self.config_label = ctk.CTkLabel(self.config_header_frame, text="当前屏蔽配置 (config.ini):", anchor="w")
        self.config_label.pack(side="left", padx=(0,5))

        self.update_config_button = ctk.CTkButton(self.config_header_frame, text="更新配置", command=self.fetch_and_update_local_config, width=80) 
        self.update_config_button.pack(side="right", padx=(0,0)) 

        self.config_display_textbox = ctk.CTkTextbox(self.config_display_outer_frame, wrap="word", height=100, font=("Consolas", 10), state="disabled") 
        self.config_display_textbox.pack(pady=(0,5), padx=0, fill="both", expand=True)


        # --- 日志文本框 ---
        self.log_label = ctk.CTkLabel(self.current_frame, text="运行日志:", anchor="w")
        self.log_label.pack(pady=(5,2), padx=0, fill="x")
        self.log_textbox = ctk.CTkTextbox(self.current_frame, wrap="word", height=150, font=("Consolas", 11)) 
        self.log_textbox.pack(pady=(0,10), padx=0, fill="both", expand=True)
        self.log_textbox.configure(state="disabled") 

        print("[GUI_MAIN_UI] 主界面已设置。")
        self.log_to_gui("[GUI] 主操作界面已加载。") 
        if self.certificate_installed_successfully:
            self.log_to_gui("[GUI] CA证书已安装。") 
        self.update_main_status_text("状态: 未开启保护") 
        self.check_and_create_local_ini_if_not_exists() 
        self.display_local_config_content() 
        # if not self.certificate_checked_on_startup: self.check_admin_privileges_on_startup() # 由 main 块处理

    def fetch_and_update_local_config(self):
        print("[CMD_CONFIG_UPDATE] 用户点击了“更新配置”按钮。")
        self.log_to_gui("[配置更新] 正在从远程URL更新本地 config.ini...")
        
        remote_url = DEFAULT_REMOTE_CONFIG_URL 
        self.log_to_gui(f"[配置更新] 目标URL: {remote_url}")
        print(f"[CMD_CONFIG_UPDATE] 目标URL: {remote_url}")

        try:
            self.update_main_status_text(f"状态: 正在下载配置...") 
            self.log_to_gui(f"正在下载配置: {remote_url}...")
            response = requests.get(remote_url, timeout=15) 
            response.raise_for_status() 
            
            remote_data = response.json() 
            print(f"[CMD_CONFIG_UPDATE] 从远程获取到的原始JSON数据: {remote_data}")

            filter_out_addresses_value = remote_data.get("FilterOutAddresses")

            if filter_out_addresses_value is None:
                self.log_to_gui("[配置更新错误] 远程JSON中未找到 'FilterOutAddresses' 键。")
                print("[CMD_CONFIG_UPDATE_ERROR] 远程JSON中未找到 'FilterOutAddresses' 键。")
                messagebox.showerror("配置错误", "远程配置文件格式不正确：缺少 'FilterOutAddresses'。")
                self.update_main_status_text("状态: 远程配置格式错误")
                return

            if isinstance(filter_out_addresses_value, list):
                addresses_str_to_write = ",".join([str(addr).strip() for addr in filter_out_addresses_value])
            elif isinstance(filter_out_addresses_value, str):
                addresses_str_to_write = ",".join([addr.strip() for addr in filter_out_addresses_value.split(',') if addr.strip()])
            else:
                self.log_to_gui(f"[配置更新错误] 远程JSON中 'FilterOutAddresses' 的值类型不受支持: {type(filter_out_addresses_value)}。")
                print(f"[CMD_CONFIG_UPDATE_ERROR] 远程JSON中 'FilterOutAddresses' 的值类型不受支持.")
                messagebox.showerror("配置错误", f"远程配置文件格式不正确：'FilterOutAddresses' 值类型错误。")
                self.update_main_status_text("状态: 远程配置格式错误")
                return

            config_editor = configparser.ConfigParser()
            
            if os.path.exists(self.local_config_path):
                config_editor.read(self.local_config_path, encoding='utf-8') 
            if not config_editor.has_section('MatchmakingFilter'):
                config_editor.add_section('MatchmakingFilter')
                print(f"[CMD_CONFIG_UPDATE] 在 {CONFIG_INI_FILENAME} 中创建了 [MatchmakingFilter] 节。")
            
            config_editor.set('MatchmakingFilter', 'FilterOutAddresses', addresses_str_to_write)
            
            with open(self.local_config_path, 'w', encoding='utf-8') as configfile:
                config_editor.write(configfile)
            
            self.log_to_gui(f"[配置更新] 本地 {CONFIG_INI_FILENAME} 已成功被远程配置覆盖。")
            self.log_to_gui(f"           新的 FilterOutAddresses: {addresses_str_to_write}")
            print(f"[CMD_CONFIG_UPDATE] 本地 {CONFIG_INI_FILENAME} 已被远程配置覆盖。")
            messagebox.showinfo("配置更新成功", f"本地 {CONFIG_INI_FILENAME} 已从远程更新！")
            
            self.display_local_config_content() 
            self.update_main_status_text("状态: 本地配置已从远程更新") 

            if self.is_proxy_running and self.interceptor_addon_instance:
                self.log_to_gui("[配置更新] 代理正在运行，正在通知插件重新加载配置...")
                print("[CMD_CONFIG_UPDATE] 代理正在运行，通知插件重新加载配置...")
                if self.interceptor_addon_instance.read_config_file():
                     self.log_to_gui("[配置更新] 插件已重新加载本地配置。")
                     print("[CMD_CONFIG_UPDATE] 插件已重新加载本地配置。")
                else:
                     self.log_to_gui("[配置更新错误] 插件重新加载本地配置时遇到问题。")
                     print("[CMD_CONFIG_UPDATE_ERROR] 插件重新加载本地配置时遇到问题。")
            elif self.interceptor_addon_instance: 
                self.interceptor_addon_instance.read_config_file()
                self.log_to_gui("[配置更新] 代理未运行，但插件的配置列表已尝试更新。下次启动代理将使用新配置。")
                print("[CMD_CONFIG_UPDATE] 代理未运行，但插件的配置列表已尝试更新。")
            else: 
                self.log_to_gui("[配置更新] 代理尚未启动，新配置将在下次启动代理时加载。")
                print("[CMD_CONFIG_UPDATE] 代理尚未启动，新配置将在下次启动代理时加载。")


        except requests.exceptions.RequestException as e:
            self.log_to_gui(f"[配置更新错误] 下载远程配置失败: {e}")
            print(f"[CMD_CONFIG_UPDATE_ERROR] 下载远程配置失败: {e}")
            messagebox.showerror("下载错误", f"无法从 {remote_url} 下载配置。\n错误: {e}")
            self.update_main_status_text("状态: 远程配置下载失败")
        except json.JSONDecodeError: 
            self.log_to_gui("[配置更新错误] 解析远程JSON配置失败。请确保URL返回的是有效的JSON。")
            print("[CMD_CONFIG_UPDATE_ERROR] 解析远程JSON配置失败。")
            messagebox.showerror("格式错误", "远程配置文件不是有效的JSON格式。")
            self.update_main_status_text("状态: 远程配置格式错误")
        except IOError as e:
            self.log_to_gui(f"[配置更新错误] 写入本地 {CONFIG_INI_FILENAME} 失败: {e}")
            print(f"[CMD_CONFIG_UPDATE_ERROR] 写入本地 {CONFIG_INI_FILENAME} 失败: {e}")
            messagebox.showerror("文件写入错误", f"无法更新本地配置文件。\n错误: {e}")
            self.update_main_status_text("状态: 本地配置文件写入失败")
        except Exception as e:
            self.log_to_gui(f"[配置更新错误] 更新配置时发生未知错误: {e}")
            print(f"[CMD_CONFIG_UPDATE_ERROR] 更新配置时发生未知错误: {e}")
            traceback.print_exc(file=sys.stdout)
            messagebox.showerror("未知错误", f"更新配置时发生错误。\n详情请查看CMD窗口输出。")
            self.update_main_status_text("状态: 配置更新时发生未知错误")

    def display_local_config_content(self):
        if hasattr(self, 'config_display_textbox') and self.config_display_textbox.winfo_exists():
            print(f"[CMD_DEBUG] 正在更新GUI中的config.ini显示...")
            try:
                if os.path.exists(self.local_config_path):
                    with open(self.local_config_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    self.config_display_textbox.configure(state="normal")
                    self.config_display_textbox.delete("1.0", tk.END)
                    self.config_display_textbox.insert("1.0", content if content.strip() else "<配置文件为空或仅包含注释>")
                    self.config_display_textbox.configure(state="disabled")
                    print(f"[CMD_DEBUG] config.ini内容已更新到GUI。")
                else:
                    self.config_display_textbox.configure(state="normal")
                    self.config_display_textbox.delete("1.0", tk.END)
                    self.config_display_textbox.insert("1.0", f"< {CONFIG_INI_FILENAME} 文件未找到 >")
                    self.config_display_textbox.configure(state="disabled")
                    print(f"[CMD_DEBUG] {CONFIG_INI_FILENAME} 未找到，GUI显示提示。")
            except Exception as e:
                error_msg = f"读取或显示 {CONFIG_INI_FILENAME} 失败: {e}"
                print(f"[CMD_ERROR] {error_msg}")
                self.log_to_gui(f"[配置显示错误] {error_msg}")
                if hasattr(self, 'config_display_textbox') and self.config_display_textbox.winfo_exists():
                    self.config_display_textbox.configure(state="normal")
                    self.config_display_textbox.delete("1.0", tk.END)
                    self.config_display_textbox.insert("1.0", f"<无法加载配置文件: {e}>")
                    self.config_display_textbox.configure(state="disabled")
        else:
            print("[CMD_DEBUG] Config display textbox 不存在，无法更新。")


    def check_admin_privileges_on_startup(self): # 重命名，更清晰
        if not is_admin(): # 直接调用全局函数
            warning_message = "警告: 非管理员权限，证书和代理设置可能失败。"
            if hasattr(self, 'initial_status_label') and self.initial_status_label.winfo_exists():
                self.initial_status_label.configure(text=warning_message)
            elif hasattr(self, 'status_label') and self.status_label.winfo_exists(): 
                self.log_to_gui(warning_message) 
                self.update_main_status_text("状态: 未开启保护 (非管理员)")
            else: print(warning_message) 
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
            opts = mitmproxy_options.Options(listen_host="127.0.0.1", listen_port=0)
            temp_master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            print("[CMD_CERT_GEN_THREAD] 临时DumpMaster已创建。")
            self.log_to_gui("[证书生成] 临时mitmproxy实例已创建。")

            async def run_with_timed_shutdown():
                run_task = loop.create_task(temp_master.run())
                try:
                    await asyncio.sleep(3) 
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


        if not is_admin(): # 直接调用全局函数
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
            
            active_install_button = self.large_install_cert_button if hasattr(self, 'large_install_cert_button') and self.large_install_cert_button.winfo_exists() else self.install_cert_button_main
            if active_install_button: active_install_button.configure(state="disabled", text="正在生成...")
            self.update_idletasks()

            self.cert_gen_thread = threading.Thread(target=self._run_mitmproxy_for_cert_generation, daemon=True)
            self.cert_gen_thread.start()
            
            def wait_and_recheck():
                if self.cert_gen_thread and self.cert_gen_thread.is_alive():
                    self.after(100, wait_and_recheck) 
                    return
                
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
                    self._execute_cert_install(cert_path) 

            self.after(100, wait_and_recheck) 
            return 

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
                self.log_to_gui("[GUI] CA证书已安装。") 
                if status_label_to_update and status_label_to_update.winfo_exists():
                     status_label_to_update.configure(text="状态: 证书安装成功！")

                messagebox.showinfo("证书安装成功", "mitmproxy CA证书已成功安装！\n您可能需要重启相关应用程序。\n即将加载主操作界面。")
                self.certificate_installed_successfully = True 
                
                if hasattr(self, 'large_install_cert_button') and self.large_install_cert_button.winfo_exists():
                    self.after(100, self.setup_main_ui) 
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


    def check_and_create_local_ini_if_not_exists(self): 
        if not os.path.exists(self.local_config_path):
            log_msg = f"[配置] 本地 '{CONFIG_INI_FILENAME}' 未找到，正在创建默认文件..."
            self.log_to_gui(log_msg)
            print(f"[CMD_CONFIG] {log_msg}")
            try:
                default_config = configparser.ConfigParser()
                default_config.add_section('MatchmakingFilter')
                default_config.set('MatchmakingFilter', '# FilterOutAddresses: 使用英文逗号分隔多个 IP:端口 地址', None)
                default_config.set('MatchmakingFilter', 'FilterOutAddresses', '1.2.3.4:5555,127.0.0.1:7777') 
                with open(self.local_config_path, "w", encoding="utf-8") as f:
                    default_config.write(f) 
                log_msg_created = f"[配置] 默认 '{CONFIG_INI_FILENAME}' 已创建。"
                self.log_to_gui(log_msg_created)
                print(f"[CMD_CONFIG] {log_msg_created}")
            except Exception as e:
                log_msg_error = f"[配置错误] 创建默认 {CONFIG_INI_FILENAME} 失败: {e}"
                self.log_to_gui(log_msg_error)
                print(f"[CMD_CONFIG_ERROR] {log_msg_error}")

    def log_to_gui(self, message): 
        if hasattr(self, 'log_textbox') and self.log_textbox and self.log_textbox.winfo_exists():
            def _update():
                if self.log_textbox.winfo_exists():
                    self.log_textbox.configure(state="normal") 
                    self.log_textbox.insert(tk.END, str(message) + "\n")
                    self.log_textbox.see(tk.END)
                    self.log_textbox.configure(state="disabled") 
            self.log_textbox.after(0, _update)
        else: 
            print(f"[GUI_LOG_FALLBACK] {message}")


    def update_main_status_text(self, status_text: str): 
        target_label = None
        if hasattr(self, 'status_label') and self.status_label and self.status_label.winfo_exists():
            target_label = self.status_label
        elif hasattr(self, 'initial_status_label') and self.initial_status_label and self.initial_status_label.winfo_exists(): 
            target_label = self.initial_status_label
        
        if target_label:
            def _update():
                if target_label.winfo_exists(): 
                    target_label.configure(text=status_text) 
            target_label.after(0, _update)


    def mitmproxy_runner(self):
        print("[CMD_THREAD] mitmproxy_runner 线程已启动。") 
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        print(f"[CMD_THREAD] 已为线程 {threading.get_ident()} 创建并设置新的 asyncio 事件循环。")

        try:
            print("[CMD_THREAD] 正在创建 PacketInterceptor 插件实例...")
            self.interceptor_addon_instance = PacketInterceptor(self) 
            print("[CMD_THREAD] PacketInterceptor 实例已创建。")

            print("[CMD_THREAD] 正在创建 mitmproxy 选项...")
            opts = mitmproxy_options.Options(
                listen_host="0.0.0.0",
                listen_port=int(PROXY_ADDRESS.split(':')[1]),
                allow_hosts=[ALLOWED_HOST_REGEX] 
            )
            print(f"[CMD_THREAD] mitmproxy 选项已创建，allow_hosts: {opts.allow_hosts}")
            self.log_to_gui(f"[代理核心] 配置为仅拦截域名: {ALLOWED_HOST_REGEX}")


            print("[CMD_THREAD] 正在创建 DumpMaster...")
            self.mitm_master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            self.mitm_master.addons.add(self.interceptor_addon_instance) 
            
            print("[CMD_THREAD] DumpMaster 实例已创建，并已添加插件。")
            
            self.is_proxy_running = True 
            self.after(0, lambda: self.update_main_status_text("状态: 已开启保护")) 
            self.after(0, lambda: self.start_button.configure(state="disabled"))
            self.after(0, lambda: self.stop_button.configure(state="normal"))
            self.after(0, lambda: self.update_config_button.configure(state="disabled")) 
            self.log_to_gui(f"[服务状态] 服务已在 {PROXY_ADDRESS} 端口启动。") 


            print("[CMD_THREAD] 即将调用 loop.run_until_complete(self.mitm_master.run())... (此为阻塞操作)")
            loop.run_until_complete(self.mitm_master.run()) 

        except PermissionError: 
            self.log_to_gui("[代理核心错误] 启动代理失败：权限不足。请以管理员身份运行本程序。")
            print("[CMD_ERROR] 启动代理失败：权限不足。")
        except OSError as e:
            if "address already in use" in str(e).lower() or "10048" in str(e):
                 self.log_to_gui(f"[代理核心错误] 启动代理失败：端口 {PROXY_ADDRESS.split(':')[1]} 已被占用。")
                 print(f"[CMD_ERROR] 启动代理失败：端口 {PROXY_ADDRESS.split(':')[1]} 已被占用。")
            else:
                self.log_to_gui(f"[代理核心错误] 启动代理时发生OS错误: {e}")
                print(f"[CMD_ERROR] 启动代理时发生OS错误: {e}")
        except Exception as e:
            self.log_to_gui(f"[代理核心错误] 启动或运行mitmproxy时发生意外错误: {e}")
            print(f"[CMD_ERROR] 启动或运行mitmproxy时发生意外错误: {e}")
            traceback_str = traceback.format_exc() 
            self.log_to_gui(f"[代理核心错误] 详细追溯: {traceback_str}")
            print(f"[CMD_ERROR] 详细追溯: {traceback_str}")
        finally:
            print("[CMD_THREAD] mitmproxy_runner 线程的 finally 块执行。")
            
            print("[CMD_THREAD] 正在关闭事件循环...")
            if loop and not loop.is_closed():
                tasks = [t for t in asyncio.all_tasks(loop=loop) if t is not asyncio.current_task(loop=loop)]
                if tasks:
                    for task in tasks:
                        if not task.done(): task.cancel() 
                    try:
                        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
                    except asyncio.CancelledError:
                        print("[CMD_THREAD_FINALLY] asyncio.gather 在关闭事件循环时被取消。")
                    except RuntimeError as e: 
                        print(f"[CMD_THREAD_FINALLY] 关闭事件循环中的任务时出错: {e}")
                
                if loop.is_running(): 
                    loop.call_soon_threadsafe(loop.stop) 
                if not loop.is_closed(): 
                    loop.close()
                    print("[CMD_THREAD] 事件循环已关闭。")
                else:
                    print("[CMD_THREAD] 事件循环先前已关闭。")

            self.is_proxy_running = False 
            if hasattr(self, 'start_button') and self.start_button.winfo_exists():
                 self.after(0, lambda: self.start_button.configure(text="启动保护功能", state="normal"))
            if hasattr(self, 'stop_button') and self.stop_button.winfo_exists():
                self.after(0, lambda: self.stop_button.configure(text="停止保护功能", state="disabled"))
            if hasattr(self, 'update_config_button') and self.update_config_button.winfo_exists(): 
                self.after(0, lambda: self.update_config_button.configure(state="normal"))
            self.after(0, lambda: self.update_main_status_text("状态: 未开启保护")) 
            self.mitm_master = None
            self.interceptor_addon_instance = None 
            print("[CMD_DEBUG] mitmproxy DumpMaster 已停止。")
            
            # 检查是否因为停止按钮或关闭窗口而需要关闭应用
            if self.app_should_close_after_proxy_stop:
                print("[CMD_THREAD] 检测到 app_should_close_after_proxy_stop 为 True，准备关闭应用。")
                self.after(100, self.destroy_app_safely) # 延迟关闭GUI


    def start_proxy_thread(self):
        if not is_admin(): 
            self.log_to_gui("[权限错误] 必须以管理员身份运行才能启动代理并修改系统设置。")
            print("[CMD_ERROR] 启动代理失败：需要管理员权限。")
            messagebox.showerror("权限错误", "启动代理和修改系统设置需要管理员权限。\n请以管理员身份重新运行此程序。")
            return

        if not self.certificate_installed_successfully:
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
        self.app_should_close_after_proxy_stop = False # 重置关闭标志
        self.mitm_thread = threading.Thread(target=self.mitmproxy_runner, daemon=True)
        self.mitm_thread.start()

    def stop_proxy_thread_with_confirm(self): 
        print("[CMD_DEBUG] stop_proxy_thread_with_confirm() 被调用。")
        if not self.is_proxy_running and not self.mitm_master: 
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
            self.terminate_squadgame_process() # 先关闭游戏
            self.app_should_close_after_proxy_stop = True # 设置标志，以便在代理完全停止后关闭应用
            self.stop_proxy_thread() # 然后停止代理
        else:
            self.log_to_gui("[操作] 用户取消了停止保护功能的操作。")
            print("[CMD_DEBUG] 用户取消了停止保护功能的操作。")


    def stop_proxy_thread(self): # 不再需要 close_app_after 参数
        print(f"[CMD_DEBUG] stop_proxy_thread() 内部逻辑被调用。") 
        
        if not self.is_proxy_running and not self.mitm_master : 
            print("[CMD_DEBUG] 代理未在运行中或 master 未初始化（内部），停止请求被忽略。")
            # 如果代理未运行，但 app_should_close_after_proxy_stop 为 True，说明是用户想关闭
            if self.app_should_close_after_proxy_stop:
                self.destroy_app_safely()
            return

        self.log_to_gui("[操作] 正在尝试停止保护功能...")
        print("[CMD_DEBUG] 正在尝试停止保护功能...")
        if self.mitm_master:
            try:
                if hasattr(self.mitm_master, 'should_exit') and self.mitm_master.event_loop and self.mitm_master.event_loop.is_running():
                    if self.mitm_master.should_exit.is_set(): 
                        print("[CMD_DEBUG] mitm_master 已经在关闭过程中。")
                    else:
                        self.mitm_master.event_loop.call_soon_threadsafe(self.mitm_master.should_exit.set)
                        self.log_to_gui("[操作] 已请求 mitmproxy 关闭。") 
                        print("[CMD_DEBUG] 已请求 mitmproxy 关闭 (通过 should_exit 事件)。")
                # (其余的 elif 和 else 逻辑保持不变，用于处理 mitm_master 状态异常的情况)
                elif not (hasattr(self.mitm_master, 'should_exit') and self.mitm_master.event_loop and self.mitm_master.event_loop.is_running()):
                     print("[CMD_DEBUG] mitm_master 或其事件循环已不可用，可能已停止。")
                     self.is_proxy_running = False 
                     if hasattr(self, 'start_button') and self.start_button.winfo_exists():
                        self.start_button.configure(text="启动保护功能", state="normal") 
                     if hasattr(self, 'stop_button') and self.stop_button.winfo_exists():
                        self.stop_button.configure(text="停止保护功能", state="disabled") 
                     if hasattr(self, 'update_config_button') and self.update_config_button.winfo_exists():
                        self.update_config_button.configure(state="normal")
                     self.update_main_status_text("状态: 未开启保护 (可能已意外停止)") 
                     if self.app_should_close_after_proxy_stop: # 如果是因为要关闭应用而停止
                         self.destroy_app_safely()

            except Exception as e:
                self.log_to_gui(f"[操作错误] 请求 mitmproxy 关闭时出错: {e}")
                print(f"[CMD_ERROR] 请求 mitmproxy 关闭时出错: {e}")
                traceback.print_exc(file=sys.stdout)
                if self.app_should_close_after_proxy_stop: # 出错也要尝试关闭
                    self.destroy_app_safely()
        else: # self.mitm_master 为 None
            print("[CMD_DEBUG] self.mitm_master 为 None，无法停止。")
            self.is_proxy_running = False 
            if hasattr(self, 'start_button') and self.start_button.winfo_exists():
                self.start_button.configure(text="启动保护功能", state="normal")
            if hasattr(self, 'stop_button') and self.stop_button.winfo_exists():
                self.stop_button.configure(text="停止保护功能", state="disabled")
            if hasattr(self, 'update_config_button') and self.update_config_button.winfo_exists():
                self.update_config_button.configure(state="normal")
            self.update_main_status_text("状态: 未开启保护 (Master丢失)")
            if self.app_should_close_after_proxy_stop: # 如果是因为要关闭应用而停止
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
                        p.terminate() 
                        p.wait(timeout=3) 
                        print(f"[CMD_PROCESS] 已终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']})")
                        self.log_to_gui(f"[操作] 已终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']})")
                        terminated_count +=1
                    except psutil.NoSuchProcess:
                        print(f"[CMD_PROCESS] 进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 在尝试终止时已不存在。")
                        self.log_to_gui(f"[操作] 进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 在尝试终止时已不存在。")
                    except psutil.TimeoutExpired:
                        print(f"[CMD_PROCESS_WARN] 终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 超时，尝试强制结束。")
                        self.log_to_gui(f"[操作警告] 终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 超时，尝试强制结束。")
                        p.kill() 
                        self.log_to_gui(f"[操作] 已强制结束进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']})")
                        terminated_count +=1
                    except Exception as e:
                        print(f"[CMD_PROCESS_ERROR] 终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 时发生错误: {e}")
                        self.log_to_gui(f"[操作错误] 终止进程 {TARGET_EXE_NAME} (PID: {proc.info['pid']}) 时发生错误: {e}")
            if terminated_count == 0:
                self.log_to_gui(f"[操作] 未找到正在运行的 {TARGET_EXE_NAME} 进程进行关闭。")
                print(f"[CMD_PROCESS] 未找到正在运行的 {TARGET_EXE_NAME} 进程。")

        except Exception as e:
            print(f"[CMD_PROCESS_ERROR] 遍历或终止进程时发生错误: {e}")
            self.log_to_gui(f"[操作错误] 遍历或终止进程时发生错误: {e}")

    def destroy_app_safely(self):
        print("[CMD_DEBUG] destroy_app_safely() 被调用。准备关闭GUI。")
        # 确保所有待处理的GUI更新完成
        self.update_idletasks() 
        if hasattr(self, '_original_stdout') and self._original_stdout is not None:
             sys.stdout = self._original_stdout
        if hasattr(self, '_original_stderr') and self._original_stderr is not None:
             sys.stderr = self._original_stderr
        self.destroy()


    def on_closing(self):
        self.log_to_gui("[应用] 正在关闭应用程序...")
        print("[CMD_DEBUG] 正在关闭应用程序...")
        if self.is_proxy_running:
            self.log_to_gui("[应用] 正在停止保护功能...") 
            print("[CMD_DEBUG] 正在停止保护功能...")
            
            user_confirmation = messagebox.askyesno(
                "确认关闭",
                "保护功能仍在运行。关闭程序前会尝试停止保护并关闭游戏客户端。\n\n您确定要关闭吗？"
            )
            if user_confirmation:
                self.terminate_squadgame_process() # 先关闭游戏
                self.app_should_close_after_proxy_stop = True # 设置标志
                self.stop_proxy_thread() # 请求停止代理
                # destroy_app_safely 将在 mitmproxy_runner 的 finally 中被调用
            else:
                self.log_to_gui("[应用] 用户取消了关闭操作。")
                print("[CMD_DEBUG] 用户取消了关闭操作。")
                return # 不关闭窗口
        else:
            self.destroy_app_safely() 


if __name__ == "__main__":
    # import json # 已在顶部全局导入
    
    # 尝试在程序启动时请求管理员权限（如果尚未获得）
    if os.name == 'nt' and not is_admin():
        print("[MAIN] 检测到非管理员权限，尝试提权...")
        if run_as_admin(): # 尝试提权
            print("[MAIN] 提权请求已发送，原进程即将退出。如果UAC通过，新进程将以管理员身份启动。")
            sys.exit() # 原非管理员进程退出
        else:
            print("[MAIN_ERROR] 提权失败或用户取消。程序可能无法正常工作。")
            # 在GUI完全初始化前，Tkinter的messagebox可能无法正常工作
            # 可以考虑用 ctypes 创建一个简单的Windows消息框
            ctypes.windll.user32.MessageBoxW(0, "程序需要管理员权限才能正常运行。\n请以管理员身份重新启动。", "权限不足", 0x10 | 0x0) # MB_ICONERROR | MB_OK
            sys.exit(1)
    
    if sys.platform == "win32":
        try:
            if threading.current_thread() is threading.main_thread():
                if sys.version_info >= (3, 8) and os.name == 'nt': 
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                    print("[MAIN] 已尝试设置 Windows asyncio 事件循环策略。")
        except Exception as e:
            print(f"[MAIN_ERROR] 无法设置 WindowsSelectorEventLoopPolicy: {e}")
    
    app = App()
    print("[MAIN] App 实例已创建，即将进入 mainloop...")
    app.mainloop()
    print("[MAIN] App mainloop 已退出。")

