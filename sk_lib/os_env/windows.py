import ctypes
import json
import os
import subprocess
import sys
import winreg

from loguru import logger


class WindowsEnv:
    _SCOPE_CHOICES = ("process", "user", "machine")

    @staticmethod
    def run_cmd(cmd: str, check: bool = False, encoding: str = "utf-8", **kwargs) -> tuple[bool, str]:
        """
        执行 shell 命令并返回标准输出。

        Args:
            cmd: 要执行的命令（字符串形式）
            check: 是否在命令失败时抛出异常，默认 False（返回错误信息）
            encoding: 输出编码，默认 'utf-8'，中文 Windows 系统可能需要 'gbk'
            **kwargs: 传递给 subprocess.run 的额外参数，如 timeout、cwd、env 等

        Returns:
            tuple[bool, str]: (是否成功, 输出内容/错误信息)
            - 成功时：(True, stdout内容)
            - 失败时：(False, stderr内容) 或抛出异常（当 check=True 时）
        """
        logger.debug(f"Run Command: {cmd}")

        # 默认参数
        default_kwargs = {
            "shell": True,  # 使用系统的 shell 来执行命令
            "text": True,  # 以文本模式处理 stdout 和 stderr
            "encoding": encoding,  # 设置编码
            "stdout": subprocess.PIPE,  # 捕获标准输出
            "stderr": subprocess.PIPE,  # 捕获标准错误
            "errors": "replace",  # 编码错误时使用替换字符，避免崩溃
        }
        # 用户传入的参数可以覆盖默认参数
        default_kwargs.update(kwargs)

        try:
            ret = subprocess.run(cmd, check=check, **default_kwargs)
            output = ret.stdout.strip() if ret.stdout else ""
            if output:
                logger.debug(f"Command output: {output[:200]}...")  # 只记录前200字符
            return True, output

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else e.stdout.strip() if e.stdout else ""
            logger.error(f"Command failed with exit code {e.returncode}: {cmd}")
            if error_msg:
                logger.error(f"Error output: {error_msg}")

            if check:
                raise
            return False, error_msg

        except subprocess.TimeoutExpired as e:
            error_msg = f"Command timeout after {e.timeout}s: {cmd}"
            logger.error(error_msg)
            if check:
                raise
            return False, error_msg

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            if check:
                raise
            return False, str(e)

    @staticmethod
    def is_admin() -> bool:
        """检查当前进程是否具有管理员权限

        Returns:
            bool: 是否为管理员权限
        """
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logger.warning(f"检查管理员权限失败: {e}")
            return False

    @staticmethod
    def run_as_admin(cmd: str, wait: bool = True) -> tuple[bool, str]:
        """以管理员权限运行命令

        Args:
            cmd: 要执行的命令
            wait: 是否等待命令执行完成，默认 True

        Returns:
            tuple[bool, str]: (是否成功启动, 消息)
            注意：当 wait=False 时，只返回是否成功启动，不返回执行结果
        """
        if WindowsEnv.is_admin():
            logger.info("当前已是管理员权限，直接执行命令")
            return WindowsEnv.run_cmd(cmd)

        logger.info("请求管理员权限执行命令...")

        try:
            # 使用 PowerShell 的 Start-Process 以管理员身份运行
            if wait:
                # 等待执行完成并获取结果
                powershell_cmd = f'Start-Process cmd -ArgumentList "/c {cmd}" -Verb RunAs -Wait -WindowStyle Hidden'
            else:
                # 不等待，直接启动
                powershell_cmd = f'Start-Process cmd -ArgumentList "/c {cmd}" -Verb RunAs -WindowStyle Hidden'

            ps_cmd = f'powershell -Command "{powershell_cmd}"'
            success, output = WindowsEnv.run_cmd(ps_cmd, timeout=300 if wait else 10)

            if success:
                return True, "命令已以管理员权限执行"
            else:
                return False, f"执行失败: {output}"

        except Exception as e:
            error_msg = f"以管理员身份运行失败: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    @staticmethod
    def restart_as_admin(script_path: str = None, args: list = None) -> tuple[bool, str]:
        """以管理员权限重启当前Python脚本

        Args:
            script_path: 脚本路径，默认为当前脚本
            args: 传递给脚本的参数列表

        Returns:
            tuple[bool, str]: (是否成功, 消息)
            注意：如果成功，当前进程会退出，新进程以管理员权限启动
        """
        if WindowsEnv.is_admin():
            return True, "当前已是管理员权限"

        logger.info("尝试以管理员权限重启脚本...")

        try:
            # 获取脚本路径
            if script_path is None:
                script_path = os.path.abspath(sys.argv[0])

            # 获取参数
            if args is None:
                args = sys.argv[1:]

            # 构建命令参数
            params = f'"{script_path}"'
            if args:
                params += " " + " ".join(f'"{arg}"' for arg in args)

            logger.info(f"重启脚本: {sys.executable} {params}")

            # 使用 ShellExecuteEx 以管理员身份运行
            ret = ctypes.windll.shell32.ShellExecuteW(
                None,  # hwnd
                "runas",  # 操作类型（请求管理员权限）
                sys.executable,  # 要执行的程序（Python解释器）
                params,  # 参数
                None,  # 工作目录
                1,  # 显示方式（SW_SHOWNORMAL）
            )

            # ShellExecuteW 返回值 > 32 表示成功
            if ret > 32:
                logger.info("脚本已以管理员权限重启，当前进程将退出")
                sys.exit(0)  # 退出当前进程
            else:
                error_msg = f"请求管理员权限失败，错误码: {ret}"
                logger.error(error_msg)
                return False, error_msg

        except Exception as e:
            error_msg = f"重启脚本失败: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    @staticmethod
    def check_software_installed(software_name: str, check_cmd: str = None) -> tuple[bool, str]:
        """检查软件是否已安装

        Args:
            software_name: 软件名称（用于日志）
            check_cmd: 检查命令，默认为 "{software_name} --version"

        Returns:
            tuple[bool, str]: (是否已安装, 版本信息或错误信息)
        """
        if check_cmd is None:
            check_cmd = f"{software_name} --version"

        success, output = WindowsEnv.run_cmd(check_cmd, timeout=10)
        if success and output:
            logger.info(f"{software_name} 已安装: {output[:100]}")
            return True, output

        logger.info(f"{software_name} 未安装或检查失败")
        return False, output

    @staticmethod
    def refresh_env() -> tuple[bool, str]:
        """刷新环境变量（类似于 refreshenv 命令）

        Returns:
            tuple[bool, str]: (是否成功, 消息)
        """
        cmd = 'powershell -Command "refreshenv"'
        return WindowsEnv.run_cmd(cmd, timeout=10)

    @staticmethod
    def install_choco() -> tuple[bool, str]:
        """安装 Chocolatey 包管理工具

        Returns:
            tuple[bool, str]: (是否成功, 消息)
        """
        # 检查是否已安装
        success, output = WindowsEnv.check_software_installed("Chocolatey", "choco --version")
        if success:
            return True, f"Chocolatey 已安装，版本: {output.strip()}"

        # 检查管理员权限
        if not WindowsEnv.is_admin():
            warning_msg = "警告：当前不是管理员权限，安装可能失败"
            logger.warning(warning_msg)

        # 执行安装命令
        install_script = (
            "Set-ExecutionPolicy Bypass -Scope Process -Force; "
            "[System.Net.ServicePointManager]::SecurityProtocol = "
            "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
            "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
        )

        logger.info("开始安装 Chocolatey...")
        cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{install_script}"'
        success, output = WindowsEnv.run_cmd(cmd, timeout=300)

        if not success:
            error_msg = f"Chocolatey 安装失败: {output}"
            logger.error(error_msg)
            return False, error_msg

        logger.info("Chocolatey 安装完成，正在验证...")

        # 验证安装
        verify_success, verify_output = WindowsEnv.check_software_installed("Chocolatey", "choco --version")
        if verify_success:
            return True, f"Chocolatey 安装成功，版本: {verify_output.strip()}"
        else:
            # 可能需要刷新环境变量
            logger.info("尝试刷新环境变量后再次验证...")
            WindowsEnv.refresh_env()
            verify_success, verify_output = WindowsEnv.check_software_installed("Chocolatey", "choco --version")
            if verify_success:
                return True, f"Chocolatey 安装成功，版本: {verify_output.strip()}"
            else:
                return True, "Chocolatey 安装完成，但验证版本失败，可能需要重启终端或系统"

    @staticmethod
    def uninstall_choco(auto_elevate: bool = False) -> tuple[bool, str]:
        """卸载 Chocolatey 包管理工具

        Args:
            auto_elevate: 如果没有管理员权限，是否自动请求提升权限，默认 False

        Returns:
            tuple[bool, str]: (是否成功, 消息)
        """
        # 检查是否已安装
        success, output = WindowsEnv.check_software_installed("Chocolatey", "choco --version")
        if not success:
            logger.info("Chocolatey 未安装，无需卸载")
            return True, "Chocolatey 未安装"

        logger.info(f"检测到 Chocolatey 版本: {output.strip()}")

        # 检查管理员权限
        if not WindowsEnv.is_admin():
            if auto_elevate:
                logger.warning("当前无管理员权限，尝试以管理员身份重启脚本...")
                return WindowsEnv.restart_as_admin()
            else:
                error_msg = "错误：需要管理员权限才能卸载 Chocolatey（可以设置 auto_elevate=True 自动请求权限）"
                logger.error(error_msg)
                return False, error_msg

        # 获取 Chocolatey 安装路径
        logger.info("正在获取 Chocolatey 安装路径...")
        get_path_cmd = 'powershell -Command "$env:ChocolateyInstall"'
        path_success, choco_path = WindowsEnv.run_cmd(get_path_cmd, timeout=10)

        if not path_success or not choco_path:
            # 使用默认路径
            choco_path = r"C:\ProgramData\chocolatey"
            logger.warning(f"无法获取安装路径，使用默认路径: {choco_path}")
        else:
            choco_path = choco_path.strip()
            logger.info(f"Chocolatey 安装路径: {choco_path}")

        # 执行卸载命令
        uninstall_script = f"""
        $chocoPath = '{choco_path}'
        
        if (Test-Path $chocoPath) {{
            Write-Host "正在删除 Chocolatey 目录: $chocoPath"
            Remove-Item -Path $chocoPath -Recurse -Force -ErrorAction SilentlyContinue
            
            # 清理环境变量
            [Environment]::SetEnvironmentVariable('ChocolateyInstall', $null, 'Machine')
            [Environment]::SetEnvironmentVariable('ChocolateyInstall', $null, 'User')
            
            # 从 PATH 中移除 Chocolatey 路径
            $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
            $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
            
            if ($machinePath -like "*$chocoPath*") {{
                $newPath = ($machinePath.Split(';') | Where-Object {{ $_ -notlike "*chocolatey*" }}) -join ';'
                [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
            }}
            
            if ($userPath -like "*$chocoPath*") {{
                $newPath = ($userPath.Split(';') | Where-Object {{ $_ -notlike "*chocolatey*" }}) -join ';'
                [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            }}
            
            Write-Host "Chocolatey 卸载完成"
        }} else {{
            Write-Host "Chocolatey 目录不存在: $chocoPath"
        }}
        """

        logger.info("开始卸载 Chocolatey...")
        cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{uninstall_script}"'
        success, output = WindowsEnv.run_cmd(cmd, timeout=120)

        if not success:
            error_msg = f"Chocolatey 卸载失败: {output}"
            logger.error(error_msg)
            return False, error_msg

        logger.info("Chocolatey 卸载完成，正在验证...")

        # 验证卸载
        verify_success, verify_output = WindowsEnv.check_software_installed("Chocolatey", "choco --version")
        if not verify_success:
            logger.info("验证成功：Chocolatey 已完全卸载")
            return True, "Chocolatey 卸载成功，建议重启终端或系统以完全清除环境变量"
        else:
            warning_msg = "Chocolatey 可能未完全卸载，请重启终端后再次检查"
            logger.warning(warning_msg)
            return True, warning_msg

    @staticmethod
    def open_terminal(shell: str = "cmd", directory: str = None, as_admin: bool = False):
        """打开终端（CMD 或 PowerShell）

        Args:
            shell: 终端类型，'cmd' 或 'powershell'，默认 'cmd'
            directory: 工作目录，默认为用户主目录
            as_admin: 是否以管理员身份打开，默认 False

        Examples:
            # 打开普通 CMD
            WindowsEnv.open_terminal()

            # 以管理员身份打开 CMD
            WindowsEnv.open_terminal(as_admin=True)

            # 打开 PowerShell
            WindowsEnv.open_terminal(shell="powershell")

            # 以管理员身份打开 PowerShell 并指定目录
            WindowsEnv.open_terminal(shell="powershell", directory="C:\\Projects", as_admin=True)
        """
        if directory is None:
            directory = os.path.expanduser("~")
        abs_dir = os.path.abspath(directory)

        shell = shell.lower()
        if shell not in ["cmd", "powershell", "ps"]:
            logger.error(f"不支持的终端类型: {shell}，请使用 'cmd' 或 'powershell'")
            return

        # 统一处理 powershell 和 ps
        if shell == "ps":
            shell = "powershell"

        # 检查当前是否已是管理员
        try:
            is_current_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_current_admin = False

        if shell == "cmd":
            if as_admin:
                if is_current_admin:
                    # 已是管理员，直接启动
                    subprocess.Popen(["cmd.exe", f'/k cd /d "{abs_dir}"'], cwd=abs_dir)
                    logger.info(f"已打开 CMD（管理员），工作目录: {abs_dir}")
                else:
                    # 请求提权运行
                    ctypes.windll.shell32.ShellExecuteW(
                        None,
                        "runas",
                        "cmd.exe",
                        f'/k cd /d "{abs_dir}"',
                        abs_dir,
                        1,
                    )
                    logger.info(f"已请求管理员权限打开 CMD，工作目录: {abs_dir}")
            else:
                # 普通模式打开
                cmd = f'start cmd /k cd /d "{abs_dir}"'
                subprocess.Popen(cmd, shell=True)
                logger.info(f"已打开 CMD，工作目录: {abs_dir}")

        elif shell == "powershell":
            if as_admin:
                if is_current_admin:
                    # 已是管理员，直接启动
                    subprocess.Popen(["powershell.exe", "-NoExit", "-Command", f"Set-Location '{abs_dir}'"])
                    logger.info(f"已打开 PowerShell（管理员），工作目录: {abs_dir}")
                else:
                    # 请求提权运行
                    ctypes.windll.shell32.ShellExecuteW(
                        None,
                        "runas",
                        "powershell.exe",
                        f"-NoExit -Command \"Set-Location '{abs_dir}'\"",
                        abs_dir,
                        1,
                    )
                    logger.info(f"已请求管理员权限打开 PowerShell，工作目录: {abs_dir}")
            else:
                # 普通模式打开
                cmd = f"start powershell -NoExit -Command \"Set-Location '{abs_dir}'\""
                subprocess.Popen(cmd, shell=True)
                logger.info(f"已打开 PowerShell，工作目录: {abs_dir}")

    # ------------------------------------------------------------------ #
    # 环境变量相关方法
    # ------------------------------------------------------------------ #
    @staticmethod
    def _get_registry_info(scope: str) -> tuple[winreg.HKEYType, str]:
        scope = (scope or "").lower()
        if scope == "user":
            return winreg.HKEY_CURRENT_USER, r"Environment"
        if scope == "machine":
            return winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        raise ValueError("scope 仅支持 'process'、'user' 或 'machine'")

    @staticmethod
    def _broadcast_env_change():
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        try:
            ctypes.windll.user32.SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                ctypes.c_wchar_p("Environment"),
                SMTO_ABORTIFHUNG,
                5000,
                None,
            )
        except Exception as e:
            logger.debug(f"广播环境变量变更失败: {e}")

    @staticmethod
    def get_env_var(name: str, scope: str = "process") -> tuple[bool, str | None]:
        """
        获取环境变量

        Args:
            name: 变量名
            scope: process/user/machine
        """
        scope = scope.lower()
        if scope not in WindowsEnv._SCOPE_CHOICES:
            return False, f"scope 仅支持 {WindowsEnv._SCOPE_CHOICES}"

        if scope == "process":
            value = os.environ.get(name)
            return (True, value) if value is not None else (False, None)

        try:
            root, path = WindowsEnv._get_registry_info(scope)
            access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            key = winreg.OpenKey(root, path, 0, access)
            try:
                value, _ = winreg.QueryValueEx(key, name)
                return True, value
            finally:
                winreg.CloseKey(key)
        except FileNotFoundError:
            return False, None
        except Exception as e:
            logger.error(f"读取环境变量失败: {e}")
            return False, str(e)

    @staticmethod
    def get_all_env_vars(scope: str = "process") -> tuple[bool, dict[str, str] | str]:
        """
        获取指定范围的全部环境变量

        Args:
            scope: process/user/machine
        """
        scope = scope.lower()
        if scope not in WindowsEnv._SCOPE_CHOICES:
            return False, f"scope 仅支持 {WindowsEnv._SCOPE_CHOICES}"

        if scope == "process":
            return True, dict(os.environ)

        try:
            root, path = WindowsEnv._get_registry_info(scope)
            access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            key = winreg.OpenKey(root, path, 0, access)
            items: dict[str, str] = {}
            try:
                index = 0
                while True:
                    name, value, _ = winreg.EnumValue(key, index)
                    items[name] = value
                    index += 1
            except OSError:
                # EnumValue 抛出异常表示遍历结束
                pass
            finally:
                winreg.CloseKey(key)

            logger.info(f"获取全部环境变量: \n{json.dumps(items, indent=4)}")
            return True, items

        except Exception as e:
            logger.error(f"获取全部环境变量失败: {e}")
            return False, str(e)

    @staticmethod
    def set_env_var(
        name: str,
        value: str,
        scope: str = "user",
        update_process: bool = True,
    ) -> tuple[bool, str]:
        """
        设置环境变量
        Args:
            name: 变量名
            value: 变量值
            scope: process/user/machine
            update_process: 是否同步更新当前进程
        """
        scope = scope.lower()
        if scope not in WindowsEnv._SCOPE_CHOICES:
            return False, f"scope 仅支持 {WindowsEnv._SCOPE_CHOICES}"

        if scope == "machine" and not WindowsEnv.is_admin():
            return False, "设置系统级变量需要管理员权限"

        try:
            if scope == "process":
                os.environ[name] = value
                return True, "已更新当前进程环境变量"

            root, path = WindowsEnv._get_registry_info(scope)
            reg_type = winreg.REG_EXPAND_SZ if "%" in value else winreg.REG_SZ
            access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
            key = winreg.OpenKey(root, path, 0, access)
            try:
                winreg.SetValueEx(key, name, 0, reg_type, value)
            finally:
                winreg.CloseKey(key)

            if update_process:
                os.environ[name] = value

            WindowsEnv._broadcast_env_change()
            return True, f"{scope} 环境变量已更新"

        except PermissionError:
            return False, "写入注册表失败：权限不足"
        except Exception as e:
            logger.error(f"设置环境变量失败: {e}")
            return False, str(e)

    @staticmethod
    def append_env_var(
        name: str,
        value: str,
        scope: str = "user",
        delimiter: str = ";",
        unique: bool = True,
    ) -> tuple[bool, str]:
        """
        在现有环境变量末尾追加值，常用于 PATH
        """
        success, current = WindowsEnv.get_env_var(name, scope)
        current_value = current or ""

        parts = [p for p in current_value.split(delimiter) if p] if current_value else []
        normalized = [p.lower() for p in parts]
        target_lower = value.lower()

        if unique and target_lower in normalized:
            return True, f"{name} 已包含该值，无需追加"

        parts.append(value)
        new_value = delimiter.join(parts) if parts else value
        return WindowsEnv.set_env_var(name, new_value, scope)


if __name__ == "__main__":
    # 示例：测试各种打开终端的方法
    print("=" * 50)
    print("Windows 环境工具测试")
    print("=" * 50)

    print(json.dumps(WindowsEnv.get_all_env_vars()[1], indent=4, ensure_ascii=False))
