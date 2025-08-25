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
import platform
import requests
from collections import Counter, defaultdict
import shutil
from snapshot_manager import snapshot_manager
from snapshot_management_window import SnapshotManagementWindow

# 字体配置 - 使用更清晰的字体
DEFAULT_FONT_FAMILY = "Microsoft YaHei UI"  # 微软雅黑UI，更清晰
FALLBACK_FONT_FAMILY = "Segoe UI"  # 备用字体
MONO_FONT_FAMILY = "Consolas"  # 等宽字体

def get_best_font():
    """获取系统中最佳可用字体"""
    import tkinter.font as tkfont
    available_fonts = tkfont.families()
    
    # 按优先级检查字体
    font_priorities = [
        "Microsoft YaHei UI",
        "Microsoft YaHei", 
        "微软雅黑",
        "Segoe UI",
        "Tahoma",
        "Arial"
    ]
    
    for font in font_priorities:
        if font in available_fonts:
            return font
    
    return "Arial"  # 最后的备用字体

from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options as mitmproxy_options
from mitmproxy import http
from mitmproxy import connection

# --- 全局配置 ---
TARGET_EXE_NAME = "SquadGame.exe"
TARGET_PID = None
PROXY_ADDRESS = "127.0.0.1:8080"
LOCAL_KEYWORD_FILENAME = "clone-keyword.ini"
REMOTE_KEYWORD_CONFIG_URL = "https://xxxx.xx/xxxxr"
INTERNET_SETTINGS_PATH = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
MITMPROXY_CA_CERT_FILENAME = "mitmproxy-ca-cert.pem"
CERT_COMMON_NAME_SUBSTRING = "mitmproxy"
ALLOWED_HOST_REGEX = r"api\.epicgames\.dev"
CLONE_DETECTION_THRESHOLD = 3
GHOST_PLAYER_LOG_THRESHOLD = 4
ANTI_CLONE_KEYWORD = "anti-clone"
ENABLE_CAPACITY_VIOLATION_DETECTION = True  # 启用人数超限检测

# 服务器证书数据库 - 用于验证服务器真实性
SERVER_CERTIFICATE_DATABASE = {
    "HAL": "1009296",
    "云影": "1008745",
    "东北军": "1007892",
    "SLS": "1006543",
    # 可以根据需要添加更多服务器的证书信息
}

BYPASS_PROXY_DOMAINS = [
    "*.steampowered.com", "*.steamcommunity.com", "*.steamgames.com",
    "*.steamusercontent.com", "*.steamcontent.com", "*.steamnetwork.net",
    "*.akamaihd.net", "*.epicgames.com",
]

# Hosts modification configuration
HOSTS_DOMAINS = [
    "api.epicgames.dev",
    "eos-general.s3.amazonaws.com",
    "game.joinsquad.com",
    "game-files.offworldindustries.com",
    "license.backend.prod.offworldindustries.com"
]

SERVER_OPTIONS = [
    {"name": "瑞典", "ip": "141.147.180.87"},
    {"name": "德国", "ip": "92.223.30.44"},
    {"name": "印度", "ip": "36.255.192.246"}
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
        pass  # 静默处理代理设置错误

# --- HostsManager 类：hosts文件管理 ---
class HostsManager:
    def __init__(self):
        self.hosts_path = self._get_hosts_path()
        self.backup_path = os.path.join(os.path.dirname(__file__), "hosts_backup.txt")
        self.is_modified = False
        self.current_ip = None
    
    def _get_hosts_path(self):
        """获取hosts文件路径"""
        if platform.system() == "Windows":
            return os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'drivers', 'etc', 'hosts')
        else:
            return "/etc/hosts"
    
    def ping_server(self, ip):
        """Ping指定IP地址，返回延迟时间(ms)或None"""
        try:
            if platform.system() == "Windows":
                cmd = ["ping", "-n", "3", ip]
            else:
                cmd = ["ping", "-c", "3", ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # 解析ping结果获取平均延迟
                output = result.stdout
                if platform.system() == "Windows":
                    # Windows ping输出格式
                    import re
                    match = re.search(r'平均 = (\d+)ms', output)
                    if not match:
                        match = re.search(r'Average = (\d+)ms', output)
                    if match:
                        return int(match.group(1))
                else:
                    # Linux ping输出格式
                    match = re.search(r'avg = ([\d.]+)', output)
                    if match:
                        return int(float(match.group(1)))
            return None
        except Exception as e:
            pass  # 静默处理ping失败
            return None
    
    def backup_hosts(self):
        """备份当前hosts文件"""
        try:
            if os.path.exists(self.hosts_path):
                shutil.copy2(self.hosts_path, self.backup_path)
                return True
        except Exception as e:
            pass  # 静默处理备份失败
        return False
    
    def modify_hosts(self, target_ip):
        """修改hosts文件，添加域名映射"""
        try:
            # 先备份
            if not self.backup_hosts():
                return False
            
            # 读取当前hosts内容
            with open(self.hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # 移除已存在的相关条目
            filtered_lines = []
            for line in lines:
                line_stripped = line.strip()
                if not any(domain in line_stripped for domain in HOSTS_DOMAINS):
                    filtered_lines.append(line)
            
            # 添加新的映射
            filtered_lines.append(f"\n# Squad Clone Block Tool - EOS Optimization\n")
            for domain in HOSTS_DOMAINS:
                filtered_lines.append(f"{target_ip} {domain}\n")
            
            # 写入hosts文件
            with open(self.hosts_path, 'w', encoding='utf-8') as f:
                f.writelines(filtered_lines)
            
            self.is_modified = True
            self.current_ip = target_ip
            return True
            
        except Exception as e:
            pass  # 静默处理修改失败
            return False
    
    def restore_hosts(self):
        """还原hosts文件"""
        try:
            if self.is_modified and os.path.exists(self.backup_path):
                shutil.copy2(self.backup_path, self.hosts_path)
                self.is_modified = False
                self.current_ip = None
                return True
        except Exception as e:
            pass  # 静默处理还原失败
        return False
    
    def cleanup(self):
        """清理备份文件"""
        try:
            if os.path.exists(self.backup_path):
                os.remove(self.backup_path)
        except Exception as e:
            pass  # 静默处理清理失败

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
            new_status_text = f"{current_status_prefix} (游戏运行中)"
            if found_pid != TARGET_PID:
                self.app.log_to_gui(f"[进程检查] {TARGET_EXE_NAME} 已开启 (PID: {found_pid})")
        else:
            new_status_text = current_status_prefix
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
                # 快照模式检查 - 如果开启快照模式，直接替换数据
                if (hasattr(self.app, 'snapshot_mode_enabled') and self.app.snapshot_mode_enabled and 
                    hasattr(self.app, 'selected_snapshot_id') and self.app.selected_snapshot_id):
                    try:
                        snapshot_sessions_data = snapshot_manager.get_snapshot_data(self.app.selected_snapshot_id)
                        if snapshot_sessions_data:
                            # 构造替换数据
                            replacement_data = {
                                "sessions": snapshot_sessions_data,
                                "count": len(snapshot_sessions_data)
                            }
                            replacement_json = json.dumps(replacement_data, ensure_ascii=False)
                            flow.response.set_text(replacement_json)
                            self.app.log_to_gui(f"{gui_log_prefix}[快照模式] 已使用快照数据替换服务器列表 (快照ID: {self.app.selected_snapshot_id})")
                            return
                        else:
                            self.app.log_to_gui(f"{gui_log_prefix}[快照模式错误] 无法获取快照数据 (ID: {self.app.selected_snapshot_id})")
                    except Exception as e:
                        self.app.log_to_gui(f"{gui_log_prefix}[快照模式错误] 快照数据替换失败: {e}")
                
                data_original = json.loads(flow.response.get_text(strict=False))
                sessions_original = data_original.get("sessions", [])
                if not isinstance(sessions_original, list): return
                
                # 记录原始服务器数量
                original_count = len(sessions_original)
                remaining_sessions = list(sessions_original)
                source_server_ips = set()
                # === 新的简化4层过滤系统 ===
                
                # 第1层：关键词过滤
                sessions_after_layer1 = []
                layer1_blocked_count = 0
                if self.effective_keyword_list:
                    for session in remaining_sessions:
                        server_name = session.get("attributes", {}).get("SERVERNAME_s", "")
                        server_name_lower = server_name.lower()
                        is_blocked = False
                        for kw in self.effective_keyword_list:
                            if kw in server_name_lower:
                                layer1_blocked_count += 1
                                self.app.log_to_gui(f"{gui_log_prefix}[第1层-关键词过滤] \"{server_name}\" 包含屏蔽关键词，已过滤。")
                                is_blocked = True
                                break
                        if not is_blocked:
                            sessions_after_layer1.append(session)
                else:
                    sessions_after_layer1 = remaining_sessions
                
                if layer1_blocked_count > 0:
                    self.app.log_to_gui(f"{gui_log_prefix}[第1层-关键词过滤] 共屏蔽 {layer1_blocked_count} 个包含关键词的服务器。")
                remaining_sessions = sessions_after_layer1
                
                # 第2层：人数超限检测
                sessions_after_layer2 = []
                layer2_blocked_count = 0
                for session in remaining_sessions:
                    attributes = session.get("attributes", {})
                    try:
                        player_count = int(attributes.get("PLAYERCOUNT_l", 0))
                        public_queue = int(attributes.get("PUBLICQUEUE_l", 0))
                        max_public_players = int(attributes.get("MAXPUBLICPLAYERS_l", 100))
                        public_queue_limit = int(attributes.get("PUBLICQUEUELIMIT_l", 0))
                        
                        # 检查人数是否超限（容量违规）
                        total_capacity = player_count + public_queue
                        max_capacity = max_public_players + public_queue_limit + 10  # 允许10人的缓冲
                        
                        if total_capacity > max_capacity:
                            server_name = attributes.get("SERVERNAME_s", "未知服务器")
                            layer2_blocked_count += 1
                            self.app.log_to_gui(f"{gui_log_prefix}[第2层-人数超限检测] \"{server_name}\" 人数异常 (总人数:{total_capacity} > 最大容量:{max_capacity})，已过滤。")
                        else:
                            sessions_after_layer2.append(session)
                    except (ValueError, TypeError):
                        # 如果字段缺失或无法转换为整数，保留该服务器
                        sessions_after_layer2.append(session)
                
                if layer2_blocked_count > 0:
                    self.app.log_to_gui(f"{gui_log_prefix}[第2层-人数超限检测] 共屏蔽 {layer2_blocked_count} 个人数异常的服务器。")
                remaining_sessions = sessions_after_layer2

                # 第3层：同IP同名服务器过滤（3个以上相同名称保留人数最少的一个）
                sessions_after_layer3 = []
                layer3_blocked_count = 0
                
                # 按IP分组
                ip_groups = defaultdict(list)
                for session in remaining_sessions:
                    ip = session.get("attributes", {}).get("ADDRESSBOUND_s")
                    if ip:
                        ip_groups[ip].append(session)
                
                for ip, sessions_on_ip in ip_groups.items():
                    if len(sessions_on_ip) < 3:
                        # 少于3个服务器，直接保留
                        sessions_after_layer3.extend(sessions_on_ip)
                        continue
                    
                    # 按服务器名称分组
                    name_groups = defaultdict(list)
                    for session in sessions_on_ip:
                        server_name = session.get("attributes", {}).get("SERVERNAME_s", "")
                        name_groups[server_name].append(session)
                    
                    # 处理每个名称组
                    for server_name, same_name_sessions in name_groups.items():
                        if len(same_name_sessions) >= 3:
                            # 3个以上相同名称，保留人数最少的一个
                            min_player_session = min(same_name_sessions, 
                                key=lambda x: int(x.get("attributes", {}).get("PLAYERCOUNT_l", 0)))
                            sessions_after_layer3.append(min_player_session)
                            
                            blocked_count = len(same_name_sessions) - 1
                            layer3_blocked_count += blocked_count
                            self.app.log_to_gui(f"{gui_log_prefix}[第3层-同IP同名过滤] IP:{ip} 服务器\"{server_name}\" 检测到{len(same_name_sessions)}个相同名称，保留人数最少的，屏蔽{blocked_count}个。")
                        else:
                            # 少于3个相同名称，全部保留
                            sessions_after_layer3.extend(same_name_sessions)
                
                if layer3_blocked_count > 0:
                    self.app.log_to_gui(f"{gui_log_prefix}[第3层-同IP同名过滤] 共屏蔽 {layer3_blocked_count} 个同IP同名的重复服务器。")
                
                # 第4层：同IP不同名人数特征过滤
                sessions_after_layer4 = []
                layer4_blocked_count = 0
                
                # 重新按IP分组进行第4层过滤
                ip_groups_layer4 = defaultdict(list)
                for session in sessions_after_layer3:
                    ip = session.get("attributes", {}).get("ADDRESSBOUND_s")
                    if ip:
                        ip_groups_layer4[ip].append(session)
                
                for ip, sessions_on_ip in ip_groups_layer4.items():
                    # 检查是否有3个以上不同名称的服务器
                    server_names = [s.get("attributes", {}).get("SERVERNAME_s", "未知") for s in sessions_on_ip]
                    unique_names = set(server_names)
                    
                    if len(unique_names) >= 3 and len(sessions_on_ip) >= 3:
                        # 分析人数特征模式
                        player_patterns = {}
                        for session in sessions_on_ip:
                            attributes = session.get("attributes", {})
                            player_count = attributes.get("PLAYERCOUNT_l", 0)
                            public_queue = attributes.get("PUBLICQUEUE_l", 0)
                            settings = session.get("settings", {})
                            max_players = settings.get("maxPublicPlayers", 100)
                            
                            # 创建人数特征模式：格式为 "当前人数(+排队)/最大人数"
                            pattern = f"{player_count}(+{public_queue})/{max_players}"
                            if pattern not in player_patterns:
                                player_patterns[pattern] = []
                            player_patterns[pattern].append(session)
                        
                        # 分析是否存在"一个独特，其他相同"的模式
                        unique_pattern = None
                        clone_pattern = None
                        clone_sessions = []
                        authentic_session = None
                        
                        for pattern, sessions_with_pattern in player_patterns.items():
                            if len(sessions_with_pattern) == 1:
                                if unique_pattern is None:
                                    unique_pattern = pattern
                                    authentic_session = sessions_with_pattern[0]
                                else:
                                    # 多个独特模式，无法判断
                                    unique_pattern = None
                                    break
                            else:
                                clone_pattern = pattern
                                clone_sessions.extend(sessions_with_pattern)
                        
                        # 如果找到了明确的人数特征模式（一个独特，其他相同）
                        if unique_pattern and clone_pattern and authentic_session:
                            # 保留独特的服务器，屏蔽其他克隆服务器
                            sessions_after_layer4.append(authentic_session)
                            blocked_names = [s.get("attributes", {}).get("SERVERNAME_s", "未知") for s in clone_sessions]
                            authentic_name = authentic_session.get("attributes", {}).get("SERVERNAME_s", "未知")
                            layer4_blocked_count += len(clone_sessions)
                            self.app.log_to_gui(f"{gui_log_prefix}[第4层] IP {ip} 检测到人数特征克隆模式，保留独特服务器 \"{authentic_name}\" ({unique_pattern})，屏蔽 {len(clone_sessions)} 个克隆服务器")
                        else:
                            # 没有明确的特征模式，保留所有服务器
                            sessions_after_layer4.extend(sessions_on_ip)
                    else:
                        # 不满足第4层过滤条件，保留所有服务器
                        sessions_after_layer4.extend(sessions_on_ip)
                
                # 汇总第4层过滤结果
                if layer4_blocked_count > 0:
                    self.app.log_to_gui(f"{gui_log_prefix}[第4层-同IP不同名人数特征过滤] 共屏蔽 {layer4_blocked_count} 个具有相同人数特征的克隆服务器。")
                
                # --- 第四层过滤结果汇总和最终处理 ---
                # 最终处理：阴兵保护（修正人数不一致）
                
                final_sessions = []
                ghost_players_fixed_count = 0
                for session in sessions_after_layer4:
                    attributes = session.get("attributes", {})
                    player_count, total_players = attributes.get("PLAYERCOUNT_l"), session.get("totalPlayers")
                    if player_count is not None and total_players is not None:
                        try:
                            if int(player_count) != int(total_players):
                                server_name = attributes.get("SERVERNAME_s", "N/A")
                                self.app.log_to_gui(f"{gui_log_prefix}[阴兵保护] \"{server_name}\" 人数修正: {player_count} -> {total_players}")
                                session["attributes"]["PLAYERCOUNT_l"] = int(total_players)
                                ghost_players_fixed_count += 1
                        except (ValueError, TypeError): pass
                    final_sessions.append(session)

                if ghost_players_fixed_count > 0:
                    self.app.log_to_gui(f"{gui_log_prefix}[阴兵保护] 本次修正了 {ghost_players_fixed_count} 个服务器的人数不一致问题")

                data_original["sessions"] = final_sessions
                data_original["count"] = len(final_sessions)
                
                final_json_text = json.dumps(data_original, ensure_ascii=False)
                flow.response.set_text(final_json_text)
                
                # 快照记录功能
                if hasattr(self.app, 'snapshot_recording_enabled') and self.app.snapshot_recording_enabled:
                    try:
                        # 保存过滤后的数据为快照
                        snapshot_name = f"快照_{time.strftime('%Y%m%d_%H%M%S')}"
                        snapshot_id = snapshot_manager.save_snapshot(
                            sessions_data=final_sessions,
                            filter_stats={
                                'total_servers': original_count,
                                'filtered_servers': len(final_sessions),
                                'blocked_by_keywords': layer1_blocked_count,
                                'blocked_by_capacity': layer2_blocked_count,
                                'blocked_by_same_ip_name': layer3_blocked_count,
                                'blocked_by_same_ip_players': layer4_blocked_count,
                                'ghost_players_fixed': ghost_players_fixed_count
                            },
                            name=snapshot_name
                        )
                        self.app.log_to_gui(f"[快照记录] 已保存快照: {snapshot_name} (ID: {snapshot_id})")
                        # 更新快照选择下拉框
                        if hasattr(self.app, 'update_snapshot_combobox'):
                            self.app.update_snapshot_combobox()
                    except Exception as e:
                        self.app.log_to_gui(f"[快照记录错误] 保存快照失败: {e}")
                
        except (json.JSONDecodeError, Exception) as e:
            self.app.log_to_gui(f"[插件错误] 处理数据时发生错误: {e}")

    def request(self, flow: http.HTTPFlow):
        self.process_flow(flow, "request")

    def response(self, flow: http.HTTPFlow):
        self.process_flow(flow, "response")

# --- GUI 应用部分 ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Squad克隆屏蔽工具V5 -Squad.ICU出品")
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
        
        # 快照功能相关变量
        self.snapshot_recording_enabled = True  # 默认启用快照记录
        self.snapshot_mode_enabled = False
        self.selected_snapshot_id = None
        self.snapshot_management_window = None
        
        # 初始化hosts管理器
        self.hosts_manager = HostsManager()

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
        # 暂时注释掉自动下载远程关键字功能
        # self.fetch_remote_config_and_update_plugin(silent=True)
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
        best_font = get_best_font()
        ctk.CTkLabel(frame, text="欢迎使用 Squad克隆服屏蔽工具!\n\n程序需要CA证书以修改HTTPS流量。", font=(best_font, 16), justify="center").pack(pady=(50, 20))
        self.large_install_cert_button = ctk.CTkButton(frame, text="安装 CA 证书", command=self.install_certificate_gui_flow, height=60, font=(best_font, 20, "bold"))
        self.large_install_cert_button.pack(pady=20, padx=50, ipady=10)
        ctk.CTkLabel(frame, text="提示: 安装证书可能需要管理员权限。", text_color="gray", font=(best_font, 12)).pack(pady=(10,50))

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
        
        # 添加快照模式控件到top_frame
        best_font = get_best_font()
        
        # 快照选择下拉框
        self.snapshot_selection_var = ctk.StringVar(value="无快照")
        self.snapshot_selection_combobox = ctk.CTkComboBox(
            top_frame,
            variable=self.snapshot_selection_var,
            values=["无快照"],
            width=150,
            state="readonly",
            command=self.on_snapshot_selection_change
        )
        self.snapshot_selection_combobox.pack(side="right", padx=(5,0))
        
        # 快照模式开关
        self.snapshot_mode_var = ctk.BooleanVar(value=False)
        self.snapshot_mode_checkbox = ctk.CTkCheckBox(
            top_frame,
            text="快照模式",
            variable=self.snapshot_mode_var,
            width=80,
            font=(best_font, 11),
            command=self.on_snapshot_mode_toggle
        )
        self.snapshot_mode_checkbox.pack(side="right", padx=(5,0))
        
        config_frame = ctk.CTkFrame(self.main_frame)
        config_frame.pack(pady=5, padx=0, fill="x")
        config_header = ctk.CTkFrame(config_frame, fg_color="transparent")
        config_header.pack(fill="x", padx=0, pady=(0,2))
        ctk.CTkLabel(config_header, text="当前生效屏蔽关键字 (合并远程与本地):", anchor="w").pack(side="left", padx=(0,5))
        
        # 右侧按钮区域
        buttons_frame = ctk.CTkFrame(config_header, fg_color="transparent")
        buttons_frame.pack(side="right")
        
        self.hosts_modify_button = ctk.CTkButton(buttons_frame, text="无法刷新服务器？", command=self.show_hosts_modification_dialog, width=100)
        self.hosts_modify_button.pack(side="right", padx=(5,0))
        
        self.snapshot_manage_button = ctk.CTkButton(buttons_frame, text="快照管理", command=self.show_snapshot_management_dialog, width=80)
        self.snapshot_manage_button.pack(side="right", padx=(5,0))
        
        # 暂时注释掉刷新远程配置按钮
        # self.update_config_button = ctk.CTkButton(config_header, text="刷新远程配置", command=lambda: self.fetch_remote_config_and_update_plugin(silent=False), width=100)
        # self.update_config_button.pack(side="right", padx=(0,0))

        self.config_display_textbox = ctk.CTkTextbox(config_frame, wrap="word", height=100, font=("Consolas", 10), state="disabled")
        self.config_display_textbox.pack(pady=(0,5), padx=0, fill="both", expand=True)
        
        # 创建运行日志标题行，包含致谢信息
        log_title_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        log_title_frame.pack(pady=(5,2), padx=0, fill="x")
        
        # 左侧：运行日志标签
        ctk.CTkLabel(log_title_frame, text="运行日志:", anchor="w").pack(side="left")
        
        # 右侧：致谢信息（右对齐，增加右边距）
        credit_frame = ctk.CTkFrame(log_title_frame, fg_color="transparent")
        credit_frame.pack(side="right", padx=(0, 20))
        
        ctk.CTkLabel(credit_frame, text="致谢：", font=("Microsoft YaHei UI", 11, "bold")).pack(side="left")
        
        # MadLifer—Squad.ICU
        ctk.CTkLabel(credit_frame, text="MadLifer—", font=("Microsoft YaHei UI", 11, "bold")).pack(side="left")
        madlifer_link = ctk.CTkLabel(credit_frame, text="Squad.ICU", 
                                   font=("Microsoft YaHei UI", 11, "bold"), 
                                   text_color="#1f6aa5", cursor="hand2")
        madlifer_link.pack(side="left")
        madlifer_link.bind("<Button-1>", lambda e: self._open_url("https://squad.icu"))
        
        ctk.CTkLabel(credit_frame, text=" | ", font=("Microsoft YaHei UI", 11, "bold")).pack(side="left")
        
        # 南赛网络—南赛云
        ctk.CTkLabel(credit_frame, text="南赛网络—", font=("Microsoft YaHei UI", 11, "bold")).pack(side="left")
        nansai_link = ctk.CTkLabel(credit_frame, text="南赛云", 
                                 font=("Microsoft YaHei UI", 11, "bold"), 
                                 text_color="#1f6aa5", cursor="hand2")
        nansai_link.pack(side="left")
        nansai_link.bind("<Button-1>", lambda e: self._open_url("https://server.squadovo.cn/"))
        
        ctk.CTkLabel(credit_frame, text=" | ", font=("Microsoft YaHei UI", 11, "bold")).pack(side="left")
        
        # Teddyou—冲锋号社区
        ctk.CTkLabel(credit_frame, text="Teddyou—", font=("Microsoft YaHei UI", 11, "bold")).pack(side="left")
        teddyou_link = ctk.CTkLabel(credit_frame, text="冲锋号社区", 
                                  font=("Microsoft YaHei UI", 11, "bold"), 
                                  text_color="#1f6aa5", cursor="hand2")
        teddyou_link.pack(side="left")
        teddyou_link.bind("<Button-1>", lambda e: self._open_url("https://bctc-squad.cn/"))
        self.log_textbox = ctk.CTkTextbox(self.main_frame, wrap="word", height=150, font=("Consolas", 11), state="disabled")
        self.log_textbox.pack(pady=(0,10), padx=0, fill="both", expand=True)
        self.log_to_gui("[GUI] 主操作界面已加载。")
        
        # 显示快照记录状态
        if self.snapshot_recording_enabled:
            self.log_to_gui("[快照功能] 已启用快照记录功能。")
            self.log_to_gui("[快照功能] 每次刷新服务器列表时将自动保存快照。")
        else:
            self.log_to_gui("[快照功能] 已关闭快照记录功能。")
        
        # 初始化快照下拉框
        self.update_snapshot_combobox()
    
    def _show_snapshot_mode_modal(self):
        """显示快照模式提示的模态对话框"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("快照模式提示")
        dialog.geometry("500x320")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        
        # 居中显示
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (320 // 2)
        dialog.geometry(f"500x320+{x}+{y}")
        
        # 主框架
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # 内容框架，用于垂直居中
        content_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        content_frame.pack(expand=True, fill="both")
        
        # 提示文本
        tip_text = ("快照模式由于使用历史数据，人数数据不准是正常现象，正常过滤不了再用这"
                   "个模式。——至少它能让你好好进服务器。\n\n"
                   "如果你的历史快照没有能够过滤克隆服务器的，请云端下载国服快照。")
        
        tip_label = ctk.CTkLabel(
            content_frame,
            text=tip_text,
            font=("Microsoft YaHei UI", 14),
            justify="center",
            wraplength=450
        )
        tip_label.pack(pady=(40, 30))
        
        # 按钮框架
        button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        button_frame.pack(pady=(0, 20))
        
        # 确定按钮
        ok_button = ctk.CTkButton(
            button_frame,
            text="我知道了",
            width=120,
            height=35,
            font=("Microsoft YaHei UI", 12),
            command=dialog.destroy
        )
        ok_button.pack()
        
        # 等待对话框关闭
        dialog.wait_window()
    
    def on_snapshot_mode_toggle(self):
        """处理快照模式开关切换事件"""
        self.snapshot_mode_enabled = self.snapshot_mode_var.get()
        if self.snapshot_mode_enabled:
            if self.selected_snapshot_id:
                # 显示快照模式提示模态框
                self._show_snapshot_mode_modal()
                self.log_to_gui("[快照模式] 已启用快照模式，将使用快照数据替换Epic服务器列表。")
                self.snapshot_selection_combobox.configure(state="readonly")
            else:
                self.log_to_gui("[快照模式] 请先选择一个快照。")
                self.snapshot_mode_var.set(False)
                self.snapshot_mode_enabled = False
        else:
            self.log_to_gui("[快照模式] 已关闭快照模式，将使用Epic原始服务器列表。")
            self.snapshot_selection_combobox.configure(state="readonly")
    
    def on_snapshot_selection_change(self, selected_value):
        """处理快照选择变化事件"""
        if selected_value == "无快照":
            self.selected_snapshot_id = None
            if self.snapshot_mode_enabled:
                self.snapshot_mode_var.set(False)
                self.on_snapshot_mode_toggle()
        else:
            # 从选择的文本中提取快照ID
            snapshots_list = snapshot_manager.get_snapshots_list()
            found = False
            for snapshot in snapshots_list:
                # 构造与显示文本相同的格式进行匹配
                favorite_mark = "☆ " if snapshot['is_favorite'] else ""
                expected_text = f"{favorite_mark}{snapshot['name']}（{snapshot['formatted_time']}）[{snapshot['server_count']}服务器]"
                if selected_value == expected_text:
                    self.selected_snapshot_id = snapshot['id']
                    self.log_to_gui(f"[快照选择] 已选择快照: {snapshot['name']}")
                    found = True
                    break
            
            # 如果没有找到匹配的快照，重置选择
            if not found:
                self.selected_snapshot_id = None
                self.log_to_gui(f"[快照选择错误] 无法找到匹配的快照: {selected_value}")
    
    def update_snapshot_combobox(self):
        """更新快照选择下拉框"""
        try:
            # 保存当前选中的快照ID
            current_selected_id = self.selected_snapshot_id
            current_selected_text = self.snapshot_selection_var.get()
            
            snapshots_list = snapshot_manager.get_snapshots_list()
            
            if snapshots_list:
                values = []
                new_selected_text = "无快照"  # 默认值
                
                for snapshot in snapshots_list:
                    favorite_mark = "☆ " if snapshot['is_favorite'] else ""
                    display_text = f"{favorite_mark}{snapshot['name']}（{snapshot['formatted_time']}）[{snapshot['server_count']}服务器]"
                    values.append(display_text)
                    
                    # 如果这是当前选中的快照，更新显示文本
                    if current_selected_id and snapshot['id'] == current_selected_id:
                        new_selected_text = display_text
                
                values.insert(0, "无快照")
                self.snapshot_selection_combobox.configure(values=values)
                
                # 恢复选中状态
                self.snapshot_selection_var.set(new_selected_text)
            else:
                self.snapshot_selection_combobox.configure(values=["无快照"])
                self.snapshot_selection_var.set("无快照")
                self.selected_snapshot_id = None
        except Exception as e:
            self.log_to_gui(f"[错误] 更新快照下拉框失败: {e}")
    
    def show_snapshot_management_dialog(self):
        """显示快照管理对话框"""
        if self.snapshot_management_window is not None and self.snapshot_management_window.winfo_exists():
            self.snapshot_management_window.lift()
            return
        
        self.snapshot_management_window = SnapshotManagementWindow(self)
        self.snapshot_management_window.grab_set()

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
        # if hasattr(self, 'update_config_button'): self.update_config_button.configure(state="disabled")
    
    def update_gui_for_proxy_stop(self):
        self.update_main_status_text("状态: 未开启保护")
        if hasattr(self, 'start_button'): self.start_button.configure(state="normal")
        if hasattr(self, 'stop_button'): self.stop_button.configure(state="disabled")
        # if hasattr(self, 'update_config_button'): self.update_config_button.configure(state="normal")

    def start_proxy_thread(self):
        if not is_admin() or not self.certificate_installed_successfully or self.is_proxy_running: return
        
        # 检查Squad是否正在运行
        if self.is_squadgame_running():
            messagebox.showwarning(
                "Squad正在运行", 
                "Squad正在运行，请关闭后再启动保护。"
            )
            return
        
        # 如果Squad没有运行且Steam正在运行，自动启动Squad
        if self.is_steam_running():
            if messagebox.askyesno(
                "自动启动Squad", 
                "检测到Steam正在运行，是否自动启动Squad？"
            ):
                if not self.launch_squad_via_steam():
                    return  # 启动失败，不继续启动保护
        
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

    def is_squadgame_running(self):
        """检查SquadGame.exe是否正在运行"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and proc.info['name'].lower() == 'squadgame.exe':
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        return False
    
    def is_steam_running(self):
        """检查Steam是否正在运行"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and proc.info['name'].lower() == 'steam.exe':
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        return False
    
    def launch_squad_via_steam(self):
        """通过Steam启动Squad"""
        try:
            # 使用steam://run/393380协议启动Squad
            subprocess.run(['start', 'steam://run/393380'], shell=True, check=True)
            self.log_to_gui("正在通过Steam启动Squad...")
            return True
        except Exception as e:
            self.log_to_gui(f"启动Squad失败: {str(e)}")
            return False

    def terminate_squadgame_process(self):
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == TARGET_EXE_NAME.lower():
                    psutil.Process(proc.info['pid']).terminate()
        except (psutil.Error, Exception): pass

    def show_hosts_modification_dialog(self):
        """显示hosts修改对话框"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("EOS服务优化")
        dialog.geometry("420x400")
        dialog.transient(self)
        dialog.grab_set()
        
        # 顶部状态区域
        status_frame = ctk.CTkFrame(dialog)
        status_frame.pack(pady=10, padx=15, fill="x")
        
        status_text = "当前状态: "
        if self.hosts_manager.is_modified:
            status_text += f"已修改 (指向: {self.hosts_manager.current_ip})"
            status_color = "orange"
        else:
            status_text += "未修改"
            status_color = "gray"
            
        best_font = get_best_font()
        status_label = ctk.CTkLabel(
            status_frame, 
            text=status_text, 
            text_color=status_color, 
            font=(best_font, 12, "bold")
        )
        status_label.pack(pady=8)
        
        # 服务器选择区域
        servers_frame = ctk.CTkFrame(dialog)
        servers_frame.pack(pady=10, padx=15, fill="both", expand=True)
        
        ctk.CTkLabel(
            servers_frame, 
            text="选择服务器:", 
            font=(best_font, 13, "bold")
        ).pack(pady=(10, 5))
        
        # 存储服务器信息和延迟
        self.server_ping_labels = {}
        self.selected_server_var = ctk.StringVar(value="")
        
        # 为每个服务器创建选择框
        for i, server in enumerate(SERVER_OPTIONS):
            server_frame = ctk.CTkFrame(servers_frame)
            server_frame.pack(pady=3, padx=10, fill="x")
            
            # 单选按钮和服务器信息
            radio_frame = ctk.CTkFrame(server_frame, fg_color="transparent")
            radio_frame.pack(side="left", fill="x", expand=True)
            
            radio_button = ctk.CTkRadioButton(
                radio_frame,
                text=f"{server['name']} - {server['ip']}",
                variable=self.selected_server_var,
                value=server['ip'],
                font=(best_font, 11)
            )
            radio_button.pack(side="left", padx=8, pady=6)
            
            # 延迟显示标签
            ping_label = ctk.CTkLabel(
                radio_frame,
                text="未测试",
                text_color="gray",
                font=(best_font, 10)
            )
            ping_label.pack(side="right", padx=8, pady=6)
            self.server_ping_labels[server['ip']] = ping_label
        
        # 说明文本区域
        info_frame = ctk.CTkFrame(dialog)
        info_frame.pack(pady=10, padx=15, fill="x")
        
        # 创建包含链接的说明文本
        info_text_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        info_text_frame.pack(pady=(8, 8))
        
        # 前半部分文本
        text_part1 = ctk.CTkLabel(
            info_text_frame,
            text="说明：我们将修改你的hosts文件，将EOS服务器反代到",
            font=(best_font, 11),
            text_color="#666666"
        )
        text_part1.pack(side="left")
        
        # 羽翼城链接
        link_label = ctk.CTkLabel(
            info_text_frame,
            text="羽翼城",
            font=(best_font, 11, "underline"),
            text_color="#3b82f6",
            cursor="hand2"
        )
        link_label.pack(side="left")
        link_label.bind("<Button-1>", lambda e: webbrowser.open("https://www.dogfight360.com/blog/18627/"))
        
        # 后半部分文本
        text_part2 = ctk.CTkLabel(
            info_text_frame,
            text="提供的地址上。",
            font=(best_font, 11),
            text_color="#666666"
        )
        text_part2.pack(side="left")
        
        # 底部操作按钮区域
        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.pack(pady=15, fill="x")
        
        # 还原hosts按钮
        restore_button = ctk.CTkButton(
            button_frame,
            text="还原hosts",
            command=lambda: self.restore_hosts_file(dialog),
            font=(best_font, 11),
            fg_color="#fa7268",
            hover_color="#d63031",
            width=100
        )
        restore_button.pack(side="left", padx=(15, 5))
        
        # 延迟测试按钮
        test_button = ctk.CTkButton(
            button_frame,
            text="延迟测试",
            command=lambda: self.test_all_servers_ping(dialog),
            font=(best_font, 11),
            fg_color="#3b82f6",
            hover_color="#2563eb",
            width=100
        )
        test_button.pack(side="left", padx=5)
        
        # 应用选中服务器按钮
        apply_button = ctk.CTkButton(
            button_frame,
            text="应用选中服务器",
            command=lambda: self.apply_selected_hosts(dialog),
            font=(best_font, 11),
            fg_color="#2fa572",
            hover_color="#106A43",
            width=130
        )
        apply_button.pack(side="right", padx=(5, 15))
    
    def test_all_servers_ping(self, dialog):
        """测试所有服务器的延迟"""
        def test_ping_thread():
            try:
                # 重置最佳延迟记录
                self._best_ping = float('inf')
                self._best_server_ip = None
                
                self.log_to_gui("[延迟测试] 开始测试所有服务器延迟...")
                
                for server in SERVER_OPTIONS:
                    ip = server['ip']
                    name = server['name']
                    
                    # 更新UI显示正在测试
                    dialog.after(0, lambda ip=ip: self.server_ping_labels[ip].configure(text="测试中...", text_color="orange"))
                    
                    # 测试延迟
                    ping_time = self.hosts_manager.ping_server(ip)
                    
                    # 更新UI显示结果
                    if ping_time is not None:
                        color = "green" if ping_time < 100 else "orange" if ping_time < 200 else "red"
                        text = f"{ping_time}ms"
                        self.log_to_gui(f"[延迟测试] {name} ({ip}): {ping_time}ms")
                        
                        # 如果是最低延迟，自动选中该服务器
                        if not hasattr(self, '_best_ping') or ping_time < self._best_ping:
                            self._best_ping = ping_time
                            self._best_server_ip = ip
                            dialog.after(0, lambda ip=ip: self.selected_server_var.set(ip))
                    else:
                        color = "red"
                        text = "超时"
                        self.log_to_gui(f"[延迟测试] {name} ({ip}): 连接超时")
                    
                    dialog.after(0, lambda ip=ip, text=text, color=color: self.server_ping_labels[ip].configure(text=text, text_color=color))
                
                self.log_to_gui("[延迟测试] 所有服务器延迟测试完成")
                
            except Exception as e:
                self.log_to_gui(f"[延迟测试错误] {e}")
                dialog.after(0, lambda: messagebox.showerror("错误", f"延迟测试失败: {e}"))
        
        # 在后台线程中执行延迟测试
        threading.Thread(target=test_ping_thread, daemon=True).start()
    
    def apply_selected_hosts(self, dialog):
        """应用选中的服务器到hosts文件"""
        try:
            selected_ip = self.selected_server_var.get()
            
            if not selected_ip:
                messagebox.showwarning("提示", "请先选择一个服务器")
                return
            
            # 找到对应的服务器名称
            server_name = None
            for server in SERVER_OPTIONS:
                if server['ip'] == selected_ip:
                    server_name = server['name']
                    break
            
            # 确认对话框
            result = messagebox.askyesno(
                "确认应用", 
                f"确定要将EOS域名指向 {server_name} ({selected_ip}) 吗？\n\n这将修改系统hosts文件。"
            )
            
            if result:
                if self.hosts_manager.modify_hosts(selected_ip):
                    self.log_to_gui(f"[Hosts优化] hosts文件已修改，EOS域名指向: {server_name} ({selected_ip})")
                    messagebox.showinfo("成功", f"hosts文件已成功修改\n\n服务器: {server_name}\nIP地址: {selected_ip}")
                    dialog.destroy()
                else:
                    messagebox.showerror("错误", "修改hosts文件失败")
                    
        except Exception as e:
            self.log_to_gui(f"[Hosts应用错误] {e}")
            messagebox.showerror("错误", f"应用失败: {e}")
    

    
    def restore_hosts_file(self, dialog):
        """还原hosts文件"""
        try:
            if self.hosts_manager.restore_hosts():
                self.log_to_gui("[Hosts优化] hosts文件已还原")
                messagebox.showinfo("成功", "hosts文件已还原")
                dialog.destroy()
            else:
                messagebox.showwarning("提示", "没有需要还原的修改")
        except Exception as e:
            self.log_to_gui(f"[Hosts还原错误] {e}")
            messagebox.showerror("错误", f"还原失败: {e}")

    def _open_url(self, url):
        """打开URL链接"""
        try:
            import webbrowser
            webbrowser.open(url)
            self.log_to_gui(f"[链接] 已打开链接: {url}")
        except Exception as e:
            self.log_to_gui(f"[错误] 无法打开链接 {url}: {e}")
    
    def on_closing(self):
        # 自动还原hosts文件
        if hasattr(self, 'hosts_manager') and self.hosts_manager.is_modified:
            try:
                if self.hosts_manager.restore_hosts():
                    self.log_to_gui("[程序关闭] hosts文件已自动还原")
            except Exception as e:
                self.log_to_gui(f"[程序关闭] hosts还原失败: {e}")
        
        # 清理hosts管理器
        if hasattr(self, 'hosts_manager'):
            self.hosts_manager.cleanup()
            
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
            pass  # 静默处理事件循环策略设置失败
    app = App()
    app.mainloop()
