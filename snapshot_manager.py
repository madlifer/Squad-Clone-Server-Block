import json
import os
import time
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class Snapshot:
    """快照数据结构"""
    id: str
    name: str
    timestamp: float
    is_favorite: bool
    sessions_data: List[Dict[str, Any]]
    filter_stats: Dict[str, Any]
    
    def __post_init__(self):
        if not self.name:
            # 自动生成名称: 时间 + 服务器数量
            dt = datetime.fromtimestamp(self.timestamp)
            server_count = len(self.sessions_data)
            self.name = f"快照_{dt.strftime('%m%d_%H%M')}_{server_count}服务器"

class SnapshotManager:
    """快照管理器"""
    
    def __init__(self, app_instance=None):
        self.app = app_instance
        self.snapshots_dir = "snapshots"
        self.index_file = os.path.join(self.snapshots_dir, "snapshots_index.json")
        self.snapshots: Dict[str, Snapshot] = {}
        
        # 确保快照目录存在
        os.makedirs(self.snapshots_dir, exist_ok=True)
        
        # 加载现有快照
        self.load_snapshots()
    
    def save_snapshot(self, sessions_data: List[Dict[str, Any]], filter_stats: Dict[str, Any], name: str = "") -> str:
        """保存新快照
        
        Args:
            sessions_data: 过滤后的服务器会话数据
            filter_stats: 过滤统计信息
            name: 快照名称(可选，为空则自动生成)
            
        Returns:
            str: 快照ID
        """
        snapshot_id = str(uuid.uuid4())
        timestamp = time.time()
        
        snapshot = Snapshot(
            id=snapshot_id,
            name=name,
            timestamp=timestamp,
            is_favorite=False,
            sessions_data=sessions_data.copy(),
            filter_stats=filter_stats.copy()
        )
        
        # 保存到内存
        self.snapshots[snapshot_id] = snapshot
        
        # 保存到文件
        self._save_snapshot_to_file(snapshot)
        self._update_index()
        
        # 自动清理：保持未收藏的快照不超过10条
        self._auto_cleanup_snapshots()
        
        return snapshot_id
    
    def load_snapshots(self) -> None:
        """加载所有快照"""
        if not os.path.exists(self.index_file):
            return
            
        try:
            with open(self.index_file, 'r', encoding='utf-8') as f:
                index_data = json.load(f)
                
            for snapshot_info in index_data.get('snapshots', []):
                snapshot_id = snapshot_info['id']
                snapshot_file = os.path.join(self.snapshots_dir, f"snapshot_{snapshot_id}.json")
                
                if os.path.exists(snapshot_file):
                    with open(snapshot_file, 'r', encoding='utf-8') as f:
                        snapshot_data = json.load(f)
                        snapshot = Snapshot(**snapshot_data)
                        self.snapshots[snapshot_id] = snapshot
                        
        except Exception as e:
            print(f"加载快照失败: {e}")
    
    def delete_snapshot(self, snapshot_id: str) -> bool:
        """删除快照
        
        Args:
            snapshot_id: 快照ID
            
        Returns:
            bool: 是否删除成功
        """
        if snapshot_id not in self.snapshots:
            return False
            
        # 从内存删除
        del self.snapshots[snapshot_id]
        
        # 删除文件
        snapshot_file = os.path.join(self.snapshots_dir, f"snapshot_{snapshot_id}.json")
        if os.path.exists(snapshot_file):
            os.remove(snapshot_file)
            
        # 更新索引
        self._update_index()
        
        return True
    
    def rename_snapshot(self, snapshot_id: str, new_name: str) -> bool:
        """重命名快照
        
        Args:
            snapshot_id: 快照ID
            new_name: 新名称
            
        Returns:
            bool: 是否重命名成功
        """
        if snapshot_id not in self.snapshots:
            return False
            
        self.snapshots[snapshot_id].name = new_name
        self._save_snapshot_to_file(self.snapshots[snapshot_id])
        self._update_index()
        
        return True
    
    def toggle_favorite(self, snapshot_id: str) -> bool:
        """切换收藏状态
        
        Args:
            snapshot_id: 快照ID
            
        Returns:
            bool: 切换后的收藏状态
        """
        if snapshot_id not in self.snapshots:
            return False
            
        snapshot = self.snapshots[snapshot_id]
        snapshot.is_favorite = not snapshot.is_favorite
        
        self._save_snapshot_to_file(snapshot)
        self._update_index()
        
        return snapshot.is_favorite
    
    def get_snapshot_data(self, snapshot_id: str) -> Optional[List[Dict[str, Any]]]:
        """获取快照数据用于替换Epic数据
        
        Args:
            snapshot_id: 快照ID
            
        Returns:
            Optional[List[Dict[str, Any]]]: 快照的服务器数据，如果不存在返回None
        """
        if snapshot_id not in self.snapshots:
            return None
            
        return self.snapshots[snapshot_id].sessions_data.copy()
    
    def get_snapshots_list(self) -> List[Dict[str, Any]]:
        """获取快照列表(用于UI显示)
        
        Returns:
            List[Dict[str, Any]]: 快照信息列表
        """
        snapshots_list = []
        
        for snapshot in self.snapshots.values():
            dt = datetime.fromtimestamp(snapshot.timestamp)
            snapshots_list.append({
                'id': snapshot.id,
                'name': snapshot.name,
                'timestamp': snapshot.timestamp,
                'formatted_time': dt.strftime('%Y-%m-%d %H:%M:%S'),
                'is_favorite': snapshot.is_favorite,
                'server_count': len(snapshot.sessions_data)
            })
        
        # 按时间倒序排列
        snapshots_list.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return snapshots_list
    
    def get_snapshot_servers(self, snapshot_id: str) -> Optional[List[Dict[str, Any]]]:
        """获取快照中的服务器列表(用于管理界面显示)
        
        Args:
            snapshot_id: 快照ID
            
        Returns:
            Optional[List[Dict[str, Any]]]: 服务器信息列表
        """
        if snapshot_id not in self.snapshots:
            return None
            
        servers = []
        for session in self.snapshots[snapshot_id].sessions_data:
            # 检查数据结构类型
            if 'server_name' in session and 'ip' in session:
                # 新格式：直接从session中提取信息
                server_name = session.get('server_name', '未知服务器')
                ip_info = session.get('ip', '未知IP')
                current_players = session.get('list_players', session.get('real_players', 0))
                max_players = 0
                
                # 尝试从_orig中获取最大玩家数
                orig_data = session.get('_orig', {})
                if orig_data:
                    settings = orig_data.get('settings', {})
                    max_players = settings.get('maxPublicPlayers', 0)
            else:
                # 旧格式：从Epic API数据结构中提取服务器信息
                attributes = session.get('attributes', {})
                settings = session.get('settings', {})
                
                # 提取服务器名称 - 直接从SERVERNAME_s字段获取
                server_name = attributes.get('SERVERNAME_s', '未知服务器')
                
                # 提取IP信息 - 从ADDRESS_s字段获取IP地址
                ip_info = attributes.get('ADDRESS_s', attributes.get('ADDRESSBOUND_s', '未知IP'))
                current_players = session.get('totalPlayers', 0)
                max_players = settings.get('maxPublicPlayers', 0)
            
            servers.append({
                'name': server_name,
                'ip': ip_info,
                'current_players': current_players,
                'max_players': max_players,
                'session_data': session  # 保留完整数据用于编辑
            })
            
        return servers
    
    def update_snapshot_servers(self, snapshot_id: str, updated_sessions: List[Dict[str, Any]]) -> bool:
        """更新快照中的服务器数据
        
        Args:
            snapshot_id: 快照ID
            updated_sessions: 更新后的服务器会话数据
            
        Returns:
            bool: 是否更新成功
        """
        if snapshot_id not in self.snapshots:
            return False
            
        self.snapshots[snapshot_id].sessions_data = updated_sessions.copy()
        self._save_snapshot_to_file(self.snapshots[snapshot_id])
        
        return True
    
    def _save_snapshot_to_file(self, snapshot: Snapshot) -> None:
        """保存快照到文件"""
        snapshot_file = os.path.join(self.snapshots_dir, f"snapshot_{snapshot.id}.json")
        
        try:
            with open(snapshot_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(snapshot), f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存快照文件失败: {e}")
    
    def _update_index(self) -> None:
        """更新快照索引文件"""
        index_data = {
            'version': '1.0',
            'last_updated': time.time(),
            'snapshots': [
                {
                    'id': snapshot.id,
                    'name': snapshot.name,
                    'timestamp': snapshot.timestamp,
                    'is_favorite': snapshot.is_favorite,
                    'server_count': len(snapshot.sessions_data)
                }
                for snapshot in self.snapshots.values()
            ]
        }
        
        try:
            with open(self.index_file, 'w', encoding='utf-8') as f:
                json.dump(index_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"更新快照索引失败: {e}")
    
    def _auto_cleanup_snapshots(self) -> None:
        """自动清理快照：保持未收藏的快照不超过10条"""
        try:
            # 获取所有未收藏的快照，按时间排序（最旧的在前）
            unfavorited_snapshots = [
                snapshot for snapshot in self.snapshots.values() 
                if not snapshot.is_favorite
            ]
            unfavorited_snapshots.sort(key=lambda x: x.timestamp)
            
            # 如果未收藏的快照超过10条，删除最旧的
            if len(unfavorited_snapshots) > 10:
                snapshots_to_delete = unfavorited_snapshots[:-10]  # 保留最新的10条
                
                for snapshot in snapshots_to_delete:
                    print(f"[自动清理] 删除旧快照: {snapshot.name} ({datetime.fromtimestamp(snapshot.timestamp).strftime('%Y-%m-%d %H:%M:%S')})")
                    
                    # 从内存删除
                    if snapshot.id in self.snapshots:
                        del self.snapshots[snapshot.id]
                    
                    # 删除文件
                    snapshot_file = os.path.join(self.snapshots_dir, f"snapshot_{snapshot.id}.json")
                    if os.path.exists(snapshot_file):
                        os.remove(snapshot_file)
                
                # 重新更新索引
                if snapshots_to_delete:
                    self._update_index()
                    print(f"[自动清理] 已删除 {len(snapshots_to_delete)} 个旧快照，当前未收藏快照数量: {len(unfavorited_snapshots) - len(snapshots_to_delete)}")
                    
        except Exception as e:
            print(f"[自动清理错误] 清理快照失败: {e}")

# 全局快照管理器实例
snapshot_manager = SnapshotManager()
