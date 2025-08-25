# -*- mode: python ; coding: utf-8 -*-

# Squad克隆屏蔽工具V5 - PyInstaller配置文件
# 更新时间: 2024年

a = Analysis(
    ['gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('app_icon.ico', '.'),
        ('snapshot_manager.py', '.'),
        ('snapshot_management_window.py', '.')
    ],
    hiddenimports=[
        'customtkinter',
        'tkinter',
        'tkinter.messagebox',
        'tkinter.simpledialog',
        'mitmproxy',
        'mitmproxy.tools.dump',
        'mitmproxy.options',
        'mitmproxy.http',
        'mitmproxy.connection',
        'mitmproxy.addons',
        'mitmproxy.addons.core',
        'psutil',
        'requests',
        'winreg',
        'ctypes',
        'ctypes.wintypes',
        'subprocess',
        'threading',
        'asyncio',
        'configparser',
        'json',
        'uuid',
        'datetime',
        'collections',
        'shutil',
        'platform',
        'socket',
        'time',
        'os',
        'sys',
        're',
        'io',
        'traceback'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'cv2'
    ],
    noarchive=False,
    optimize=0,
)

# 过滤掉不必要的模块以减小文件大小
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Squad克隆屏蔽工具V5',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # 窗口模式，不显示控制台
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='app_icon.ico',
    uac_admin=True,  # 请求管理员权限
    version_file=None,
    manifest='admin.manifest'
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[
        'vcruntime140.dll',
        'msvcp140.dll',
        'api-ms-win-*.dll'
    ],
    name='Squad克隆屏蔽工具V5'
)
