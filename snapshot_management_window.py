import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from snapshot_manager import snapshot_manager
from datetime import datetime
import requests
import json
import threading

class SnapshotManagementWindow(ctk.CTkToplevel):
    """快照管理窗口"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("快照管理")
        self.geometry("1400x700")  # 扩大窗口尺寸以显示完整服务器名称
        self.resizable(True, True)
        
        # 设置窗口居中
        self.transient(parent)
        
        # 当前选中的快照
        self.selected_snapshot_id = None
        self.selected_server_index = None
        
        self.setup_ui()
        self.refresh_snapshots_list()
        
        # 绑定关闭事件
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        """设置UI界面"""
        # 主框架
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 左侧快照列表区域
        left_frame = ctk.CTkFrame(main_frame)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        ctk.CTkLabel(left_frame, text="快照列表", font=("Microsoft YaHei UI", 14, "bold")).pack(pady=(10, 5))
        
        # 快照列表框架
        snapshots_frame = ctk.CTkFrame(left_frame)
        snapshots_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # 快照列表滚动框
        self.snapshots_listbox = tk.Listbox(
            snapshots_frame,
            font=("Microsoft YaHei UI", 10),
            selectmode=tk.SINGLE,
            bg="#2b2b2b",
            fg="white",
            selectbackground="#1f538d",
            selectforeground="white",
            borderwidth=0,
            highlightthickness=0
        )
        self.snapshots_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.snapshots_listbox.bind("<<ListboxSelect>>", self.on_snapshot_select)
        
        # 快照操作按钮
        snapshot_buttons_frame = ctk.CTkFrame(left_frame)
        snapshot_buttons_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.favorite_button = ctk.CTkButton(
            snapshot_buttons_frame,
            text="收藏",
            command=self.toggle_favorite,
            width=80,
            state="disabled"
        )
        self.favorite_button.pack(side="left", padx=(0, 5))
        
        self.delete_snapshot_button = ctk.CTkButton(
            snapshot_buttons_frame,
            text="删除快照",
            command=self.delete_snapshot,
            width=80,
            state="disabled",
            fg_color="#d32f2f",
            hover_color="#b71c1c"
        )
        self.delete_snapshot_button.pack(side="left", padx=5)
        
        self.download_button = ctk.CTkButton(
            snapshot_buttons_frame,
            text="云端下载国服快照",
            command=self.download_cloud_snapshot,
            width=120,
            fg_color="#2e7d32",
            hover_color="#1b5e20"
        )
        self.download_button.pack(side="left", padx=5)
        
        # 右侧服务器详情区域
        right_frame = ctk.CTkFrame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        ctk.CTkLabel(right_frame, text="服务器详情", font=("Microsoft YaHei UI", 14, "bold")).pack(pady=(10, 5))
        
        # 服务器列表框架
        servers_frame = ctk.CTkFrame(right_frame)
        servers_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # 创建Treeview样式
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Custom.Treeview",
                       background="#2b2b2b",
                       foreground="#e0e0e0",
                       fieldbackground="#2b2b2b",
                       borderwidth=0,
                       rowheight=28,
                       font=("Microsoft YaHei UI", 10))
        style.configure("Custom.Treeview.Heading",
                       background="#1a1a1a",
                       foreground="#ffffff",
                       relief="flat",
                       borderwidth=1,
                       font=("Microsoft YaHei UI", 11, "bold"))
        style.map("Custom.Treeview",
                 background=[('selected', '#0d7377'), ('focus', '#0d7377')],
                 foreground=[('selected', 'white'), ('focus', 'white')])
        style.map("Custom.Treeview.Heading",
                 background=[('active', '#333333')],
                 foreground=[('active', '#ffffff')])
        
        # 创建Treeview组件
        self.servers_tree = ttk.Treeview(
            servers_frame,
            style="Custom.Treeview",
            columns=("name", "ip", "players"),
            show="headings",
            selectmode="browse"
        )
        
        # 设置列标题和宽度
        self.servers_tree.heading("name", text="服务器名称", anchor="w")
        self.servers_tree.heading("ip", text="IP地址", anchor="w")
        self.servers_tree.heading("players", text="在线人数", anchor="center")
        
        self.servers_tree.column("name", width=600, minwidth=300, anchor="w")
        self.servers_tree.column("ip", width=200, minwidth=150, anchor="w")
        self.servers_tree.column("players", width=120, minwidth=80, anchor="center")
        
        # 添加滚动条
        tree_scrollbar = ttk.Scrollbar(servers_frame, orient="vertical", command=self.servers_tree.yview)
        self.servers_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        # 布局Treeview和滚动条
        self.servers_tree.pack(side="left", fill="both", expand=True, padx=(5, 0), pady=5)
        tree_scrollbar.pack(side="right", fill="y", pady=5)
        
        # 绑定事件
        self.servers_tree.bind("<<TreeviewSelect>>", self.on_server_select)
        self.servers_tree.bind("<Motion>", self.on_tree_motion)
        self.servers_tree.bind("<Leave>", self.on_tree_leave)
        
        # 创建hover提示窗口
        self.tooltip = None
        self.tooltip_text = ""
        
        # 服务器操作按钮
        server_buttons_frame = ctk.CTkFrame(right_frame)
        server_buttons_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.delete_server_button = ctk.CTkButton(
            server_buttons_frame,
            text="删除服务器",
            command=self.delete_server,
            width=100,
            state="disabled",
            fg_color="#d32f2f",
            hover_color="#b71c1c"
        )
        self.delete_server_button.pack(side="left", padx=(0, 5))
        

    
    def refresh_snapshots_list(self):
        """刷新快照列表"""
        self.snapshots_listbox.delete(0, tk.END)
        
        snapshots_list = snapshot_manager.get_snapshots_list()
        for snapshot in snapshots_list:
            favorite_mark = "☆ " if snapshot['is_favorite'] else ""
            display_text = f"{favorite_mark}{snapshot['name']}（{snapshot['formatted_time']}）[{snapshot['server_count']}服务器]"
            self.snapshots_listbox.insert(tk.END, display_text)
        
        # 清空服务器列表
        for item in self.servers_tree.get_children():
            self.servers_tree.delete(item)
        self.selected_snapshot_id = None
        self.selected_server_index = None
        
        # 禁用按钮
        self.favorite_button.configure(state="disabled")
        self.delete_snapshot_button.configure(state="disabled")
        self.delete_server_button.configure(state="disabled")
    
    def _update_snapshots_display_only(self):
        """只更新快照列表的显示文本，不清空服务器列表"""
        self.snapshots_listbox.delete(0, tk.END)
        
        snapshots_list = snapshot_manager.get_snapshots_list()
        for snapshot in snapshots_list:
            favorite_mark = "☆ " if snapshot['is_favorite'] else ""
            display_text = f"{favorite_mark}{snapshot['name']}（{snapshot['formatted_time']}）[{snapshot['server_count']}服务器]"
            self.snapshots_listbox.insert(tk.END, display_text)
    
    def on_snapshot_select(self, event):
        """快照选择事件"""
        selection = self.snapshots_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        snapshots_list = snapshot_manager.get_snapshots_list()
        
        if index < len(snapshots_list):
            snapshot = snapshots_list[index]
            self.selected_snapshot_id = snapshot['id']
            
            # 启用快照操作按钮
            self.favorite_button.configure(state="normal")
            self.delete_snapshot_button.configure(state="normal")
            
            # 更新收藏按钮文本
            if snapshot['is_favorite']:
                self.favorite_button.configure(text="取消收藏")
            else:
                self.favorite_button.configure(text="收藏")
            
            # 刷新服务器列表
            self.refresh_servers_list()
    
    def refresh_servers_list(self):
        """刷新服务器列表"""
        # 清空现有数据
        for item in self.servers_tree.get_children():
            self.servers_tree.delete(item)
        
        if not self.selected_snapshot_id:
            return
        
        servers = snapshot_manager.get_snapshot_servers(self.selected_snapshot_id)
        
        if servers:
            for i, server in enumerate(servers):
                server_name = server['name']
                server_ip = server['ip']
                player_info = f"{server['current_players']}/{server['max_players']}"
                
                # 插入数据到Treeview
                item_id = self.servers_tree.insert(
                    "", "end",
                    values=(server_name, server_ip, player_info),
                    tags=(f"server_{i}",)
                )
        
        # 清除选中状态
        self.servers_tree.selection_remove(self.servers_tree.selection())
        self.selected_server_index = None
        self.delete_server_button.configure(state="disabled")
    
    def on_server_select(self, event):
        """服务器选择事件"""
        selection = self.servers_tree.selection()
        if selection:
            # 获取选中项的索引
            item = selection[0]
            children = self.servers_tree.get_children()
            self.selected_server_index = children.index(item)
            self.delete_server_button.configure(state="normal")
        else:
            self.selected_server_index = None
            self.delete_server_button.configure(state="disabled")
    
    def on_tree_motion(self, event):
        """鼠标移动事件，显示hover提示"""
        item = self.servers_tree.identify_row(event.y)
        if item:
            # 获取服务器名称
            values = self.servers_tree.item(item, 'values')
            if values:
                server_name = values[0]
                # 如果名称过长，显示完整名称的tooltip
                if len(server_name) > 50:  # 只有当名称较长时才显示tooltip
                    self.show_tooltip(event.x_root, event.y_root, server_name)
                else:
                    self.hide_tooltip()
            else:
                self.hide_tooltip()
        else:
            self.hide_tooltip()
    
    def on_tree_leave(self, event):
        """鼠标离开事件，隐藏hover提示"""
        self.hide_tooltip()
    
    def show_tooltip(self, x, y, text):
        """显示hover提示窗口"""
        if self.tooltip_text == text and self.tooltip:
            return  # 如果内容相同且tooltip已存在，不重复创建
        
        self.hide_tooltip()  # 先隐藏现有的tooltip
        
        self.tooltip_text = text
        self.tooltip = tk.Toplevel(self)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x+10}+{y+10}")
        
        # 设置tooltip样式
        label = tk.Label(
            self.tooltip,
            text=text,
            background="#2b2b2b",
            foreground="white",
            font=("Microsoft YaHei UI", 9),
            relief="solid",
            borderwidth=1,
            padx=8,
            pady=4
        )
        label.pack()
    
    def hide_tooltip(self):
        """隐藏hover提示窗口"""
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None
            self.tooltip_text = ""
    
    def rename_snapshot(self):
        """重命名快照"""
        if not self.selected_snapshot_id:
            return
        
        # 获取当前快照信息
        snapshots_list = snapshot_manager.get_snapshots_list()
        current_name = ""
        for snapshot in snapshots_list:
            if snapshot['id'] == self.selected_snapshot_id:
                current_name = snapshot['name']
                break
        
        # 弹出输入对话框
        new_name = simpledialog.askstring(
            "重命名快照",
            "请输入新的快照名称:",
            initialvalue=current_name
        )
        
        if new_name and new_name.strip():
            if snapshot_manager.rename_snapshot(self.selected_snapshot_id, new_name.strip()):
                self.refresh_snapshots_list()
                self.parent.update_snapshot_combobox()  # 更新主窗口的下拉框
                messagebox.showinfo("成功", "快照重命名成功！")
            else:
                messagebox.showerror("错误", "快照重命名失败！")
    
    def toggle_favorite(self):
        """切换收藏状态"""
        if not self.selected_snapshot_id:
            return
        
        is_favorite = snapshot_manager.toggle_favorite(self.selected_snapshot_id)
        self.refresh_snapshots_list()
        self.parent.update_snapshot_combobox()  # 更新主窗口的下拉框
        
        if is_favorite:
            messagebox.showinfo("成功", "已添加到收藏！")
        else:
            messagebox.showinfo("成功", "已取消收藏！")
    
    def delete_snapshot(self):
        """删除快照"""
        if not self.selected_snapshot_id:
            return
        
        # 确认删除
        result = messagebox.askyesno(
            "确认删除",
            "确定要删除这个快照吗？此操作不可撤销！",
            icon="warning"
        )
        
        if result:
            if snapshot_manager.delete_snapshot(self.selected_snapshot_id):
                self.refresh_snapshots_list()
                self.parent.update_snapshot_combobox()  # 更新主窗口的下拉框
                messagebox.showinfo("成功", "快照删除成功！")
            else:
                messagebox.showerror("错误", "快照删除失败！")
    
    def delete_server(self):
        """删除服务器"""
        if not self.selected_snapshot_id or self.selected_server_index is None:
            return
        
        # 确认删除
        result = messagebox.askyesno(
            "确认删除",
            "确定要删除这个服务器吗？",
            icon="warning"
        )
        
        if result:
            # 获取当前服务器列表
            servers = snapshot_manager.get_snapshot_servers(self.selected_snapshot_id)
            if servers and self.selected_server_index < len(servers):
                # 删除指定服务器
                del servers[self.selected_server_index]
                
                # 重新构建会话数据
                updated_sessions = [server['session_data'] for server in servers]
                
                # 更新快照
                if snapshot_manager.update_snapshot_servers(self.selected_snapshot_id, updated_sessions):
                    # 重新加载快照数据以确保数据同步
                    snapshot_manager.load_snapshots()
                    
                    # 强制刷新界面 - 按正确顺序执行
                    self.refresh_servers_list()
                    # 只更新快照列表的显示文本，不清空服务器列表
                    self._update_snapshots_display_only()
                    self.parent.update_snapshot_combobox()  # 更新主窗口的下拉框
                    
                    # 强制更新界面显示
                    self.update_idletasks()
                    
                    messagebox.showinfo("成功", "服务器删除成功！")
                else:
                    messagebox.showerror("错误", "服务器删除失败！")
    
    def download_cloud_snapshot(self):
        """从云端下载快照数据"""
        def download_thread():
            try:
                # 禁用下载按钮，防止重复点击
                self.download_button.configure(state="disabled", text="下载中...")
                
                # 从云端URL下载数据
                response = requests.get("https://clone.squad.icu/server", timeout=30)
                response.raise_for_status()
                
                # 解析JSON数据
                cloud_data = response.json()
                
                # 检查数据格式
                if isinstance(cloud_data, dict) and 'sessions_data' in cloud_data:
                    # 云端返回的是快照格式，直接使用sessions_data
                    sessions_data = cloud_data['sessions_data']
                    # 验证数据
                    if not isinstance(sessions_data, list) or len(sessions_data) == 0:
                        raise ValueError("云端数据格式无效或为空")
                elif isinstance(cloud_data, list):
                    # 云端返回的是原始Epic API数据数组，需要转换
                    sessions_data = self._convert_cloud_to_local_format(cloud_data)
                    if len(sessions_data) == 0:
                        raise ValueError("数据转换失败")
                else:
                    raise ValueError("云端数据格式不支持")
                
                # 生成快照名称
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                snapshot_name = f"云端快照 {timestamp}"
                
                # 保存快照
                snapshot_id = snapshot_manager.save_snapshot(
                    sessions_data,
                    {},  # filter_stats - 云端下载的快照没有过滤统计信息
                    snapshot_name
                )
                
                # 在主线程中更新UI
                self.after(0, lambda: self._download_success_callback(snapshot_name, len(sessions_data)))
                
            except requests.exceptions.RequestException as e:
                # 网络错误
                error_msg = f"网络请求失败: {str(e)}"
                self.after(0, lambda: self._download_error_callback(error_msg))
            except json.JSONDecodeError:
                # JSON解析错误
                error_msg = "云端数据格式错误，无法解析JSON"
                self.after(0, lambda: self._download_error_callback(error_msg))
            except Exception as e:
                # 其他错误
                error_msg = f"下载失败: {str(e)}"
                self.after(0, lambda: self._download_error_callback(error_msg))
            finally:
                # 恢复下载按钮
                self.after(0, lambda: self.download_button.configure(state="normal", text="云端下载"))
        
        # 在后台线程中执行下载
        threading.Thread(target=download_thread, daemon=True).start()
    
    def _download_success_callback(self, snapshot_name, server_count):
        """下载成功回调"""
        self._show_download_success_dialog(snapshot_name, server_count)
        # 刷新快照列表
        self.refresh_snapshots_list()
    
    def _show_download_success_dialog(self, snapshot_name, server_count):
        """显示下载成功对话框，包含复制群号功能"""
        dialog = ctk.CTkToplevel(self)
        dialog.title("成功！感谢 冲锋号社区 Teddyyou 提供可持续的云端快照！")
        dialog.geometry("450x280")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        
        # 居中显示
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (450 // 2)
        y = (dialog.winfo_screenheight() // 2) - (280 // 2)
        dialog.geometry(f"450x280+{x}+{y}")
        
        # 主框架
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # 内容框架，用于垂直居中
        content_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        content_frame.pack(expand=True, fill="both")
        
        # 快照信息
        info_text = f"快照名称：{snapshot_name}\n服务器数量：{server_count}"
        info_label = ctk.CTkLabel(
            content_frame,
            text=info_text,
            font=("Microsoft YaHei UI", 12),
            justify="center"
        )
        info_label.pack(pady=(30, 15))
        
        # 战队招募信息（加粗）
        recruit_label = ctk.CTkLabel(
            content_frame,
            text="冲锋号战队招募队员，点击复制群号703511605",
            font=("Microsoft YaHei UI", 12, "bold"),
            justify="center"
        )
        recruit_label.pack(pady=(0, 20))
        
        # 按钮框架
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(side="bottom", pady=(0, 10))
        
        # 复制群号按钮
        def copy_group_number():
            dialog.clipboard_clear()
            dialog.clipboard_append("703511605")
            # 临时显示复制成功提示
            copy_button.configure(text="已复制！")
            dialog.after(1000, lambda: copy_button.configure(text="复制群号"))
        
        copy_button = ctk.CTkButton(
            button_frame,
            text="复制群号",
            command=copy_group_number,
            width=80,
            fg_color="#1976d2",
            hover_color="#1565c0"
        )
        copy_button.pack(side="left", padx=(0, 10))
        
        # 确定按钮
        ok_button = ctk.CTkButton(
            button_frame,
            text="确定",
            command=dialog.destroy,
            width=80
        )
        ok_button.pack(side="left")
        
        # 设置焦点到确定按钮
        ok_button.focus_set()
    
    def _download_error_callback(self, error_msg):
        """下载失败回调"""
        messagebox.showerror("下载失败", error_msg)
    
    def _convert_cloud_to_local_format(self, raw_sessions):
        """将云端原始数据转换为本地快照格式"""
        converted_sessions = []
        
        for session in raw_sessions:
            try:
                # 云端数据结构分析：
                # session = {
                #   "deployment": "...",
                #   "id": "...",
                #   "bucket": "...",
                #   "settings": {...},
                #   "totalPlayers": int,
                #   "openPublicPlayers": int,
                #   "publicPlayers": [],
                #   "started": bool,
                #   "lastUpdated": null,
                #   "attributes": {...},
                #   "owner": "...",
                #   "ownerPlatformId": null
                # }
                
                # 提取attributes中的关键信息
                attributes = session.get('attributes', {})
                settings = session.get('settings', {})
                
                # 从attributes提取服务器信息
                server_name = attributes.get('SERVERNAME_s', '未知服务器')
                ip_address = attributes.get('ADDRESS_s', '未知IP')
                address_bound = attributes.get('ADDRESSBOUND_s', '')
                map_name = attributes.get('MAPNAME_s', '未知地图')
                team_one = attributes.get('TEAMONE_s', '')
                team_two = attributes.get('TEAMTWO_s', '')
                game_version = attributes.get('GAMEVERSION_s', '')
                
                # 从address_bound提取端口
                beacon_port = 0
                if address_bound and ':' in address_bound:
                    try:
                        beacon_port = int(address_bound.split(':')[-1])
                    except ValueError:
                        beacon_port = 0
                
                # 计算玩家信息
                total_players = session.get('totalPlayers', 0)
                max_public_players = settings.get('maxPublicPlayers', 0)
                open_public_players = session.get('openPublicPlayers', 0)
                public_queue = max(0, total_players - max_public_players) if max_public_players > 0 else 0
                
                # 构建本地格式的session数据
                local_session = {
                    'ip': ip_address,
                    'beacon_port': beacon_port,
                    'license_id': session.get('id', ''),
                    'server_name': server_name,
                    'team_one': team_one,
                    'team_two': team_two,
                    'map_name': map_name,
                    'list_players': total_players,
                    'public_queue': public_queue,
                    'uptime_sec': 0,  # 云端数据中没有这个信息
                    'game_version': game_version,
                    'real_players': total_players,
                    'last_updated': session.get('lastUpdated'),
                    '_orig': session  # 保留完整的原始数据
                }
                
                converted_sessions.append(local_session)
                
            except Exception as e:
                # 如果转换失败，记录错误但继续处理其他数据
                print(f"转换云端数据时出错: {e}")
                continue
        
        return converted_sessions
    
    def on_closing(self):
        """关闭窗口事件"""
        # 更新主窗口的快照选择下拉框
        self.parent.update_snapshot_combobox()
        self.parent.snapshot_management_window = None
        self.hide_tooltip()  # 确保关闭时隐藏tooltip
        self.destroy()
