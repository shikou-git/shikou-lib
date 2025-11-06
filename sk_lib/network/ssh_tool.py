import os
import shutil
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from functools import wraps
from typing import Generator, Any

import paramiko
from loguru import logger
from paramiko import SFTPClient


def ensure_connected(func):
    """装饰器：确保SSH已连接"""

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.is_connected():
            logger.warning("SSH连接已断开，尝试重新连接...")
            if not self.connect():
                logger.error("SSH连接失败，无法执行操作")
                # 根据函数返回类型返回适当的失败值
                return_annotation = func.__annotations__.get("return")
                if return_annotation == bool:
                    return False
                elif return_annotation == tuple[bool, str]:
                    return False, "SSH连接失败"
                else:
                    return None
        return func(self, *args, **kwargs)

    return wrapper


class SSHTool:
    def __init__(self, ip: str, port: int | None = None, username: str | None = None, password: str | None = None):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.client: paramiko.SSHClient | None = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def connect(self, timeout: int = 5) -> bool:
        """建立SSH连接"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.ip, port=self.port, username=self.username, password=self.password, timeout=timeout
            )
            logger.debug(f"SSH 连接成功: {self.username}@{self.ip}:{self.port}")
            return True

        except Exception as e:
            logger.error(f"SSH 连接 {self.ip} 失败: {e}")
            self.client = None
            return False

    def is_connected(self) -> bool:
        """检查当前连接是否有效"""
        if not self.client:
            return False

        transport = self.client.get_transport()
        return transport is not None and transport.is_active()

    def disconnect(self):
        """断开SSH连接"""
        if self.client:
            try:
                self.client.close()
                logger.debug(f"已断开SSH连接")
            except Exception as e:
                logger.error(f"断开SSH连接时出错: {e}")
            finally:
                self.client = None

    @contextmanager
    def _get_sftp(self) -> Generator[SFTPClient, None, None]:
        """获取 SFTP 客户端的上下文管理器"""
        sftp = self.client.open_sftp()
        try:
            yield sftp
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    @ensure_connected
    def run_cmd(self, command: str, timeout: int | None = None) -> tuple[bool, str]:
        """执行SSH命令

        Args:
            command: 要执行的命令
            timeout: 命令执行超时时间（秒），None表示不限制

        Returns:
            tuple[bool, str]: (是否成功, 命令输出/错误信息)
        """
        try:
            logger.debug(f"执行命令: {command}")
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

            output = stdout.read().decode("utf-8", errors="ignore").strip()
            error = stderr.read().decode("utf-8", errors="ignore").strip()
            exit_status = stdout.channel.recv_exit_status()

            if exit_status == 0:
                logger.debug(f"执行命令成功: \n{output}")
                return True, output
            else:
                logger.debug(f"执行命令失败 (exit_code={exit_status}): \n{error if error else output}")
                return False, error if error else output

        except Exception as e:
            logger.error(f"执行命令出错: {command}, 错误: {e}")
            return False, str(e)

    @ensure_connected
    def is_file(self, file_path: str) -> bool:
        """判断远程路径是否为文件"""
        try:
            with self._get_sftp() as sftp:
                file_stat = sftp.stat(file_path)
                return stat.S_ISREG(file_stat.st_mode)

        except Exception as e:
            logger.error(f"判断文件失败: {file_path}, 错误: {e}")
            raise

    @ensure_connected
    def is_dir(self, dir_path: str) -> bool:
        """判断远程路径是否为目录"""
        try:
            with self._get_sftp() as sftp:
                dir_stat = sftp.stat(dir_path)
                return stat.S_ISDIR(dir_stat.st_mode)

        except Exception as e:
            logger.error(f"判断目录失败: {dir_path}, 错误: {e}")
            raise

    @ensure_connected
    def file_exists(self, file_path: str) -> bool:
        """判断远程文件是否存在

        Args:
            file_path: 远程文件路径

        Returns:
            bool: 文件存在返回True，否则返回False
        """
        try:
            with self._get_sftp() as sftp:
                file_stat = sftp.stat(file_path)
                # 检查是否为普通文件（不是目录）
                is_file = stat.S_ISREG(file_stat.st_mode)
                if is_file:
                    logger.debug(f"文件存在: {file_path}")
                    return True
                else:
                    logger.debug(f"路径存在但不是文件: {file_path}")
                    return False

        except (IOError, OSError, FileNotFoundError):
            logger.debug(f"文件不存在: {file_path}")
            return False

        except Exception as e:
            logger.error(f"检查文件失败: {file_path}, 错误: {e}")
            raise

    @ensure_connected
    def dir_exists(self, dir_path: str) -> bool:
        """判断远程目录是否存在

        Args:
            dir_path: 远程目录路径

        Returns:
            bool: 目录存在返回True，否则返回False
        """
        try:
            with self._get_sftp() as sftp:
                dir_stat = sftp.stat(dir_path)
                # 检查是否为目录
                is_dir = stat.S_ISDIR(dir_stat.st_mode)
                if is_dir:
                    logger.debug(f"目录存在: {dir_path}")
                    return True
                else:
                    logger.debug(f"路径存在但不是目录: {dir_path}")
                    return False

        except (IOError, OSError, FileNotFoundError):
            logger.debug(f"目录不存在: {dir_path}")
            return False

        except Exception as e:
            logger.error(f"检查目录失败: {dir_path}, 错误: {e}")
            raise

    @ensure_connected
    def path_exists(self, path: str) -> bool:
        """判断远程路径是否存在（不区分文件或目录）

        Args:
            path: 远程路径

        Returns:
            bool: 路径存在返回True，否则返回False
        """
        try:
            with self._get_sftp() as sftp:
                sftp.stat(path)
                logger.debug(f"路径存在: {path}")
                return True

        except (IOError, OSError, FileNotFoundError):
            logger.debug(f"路径不存在: {path}")
            return False

        except Exception as e:
            logger.error(f"检查路径失败: {path}, 错误: {e}")
            raise

    @ensure_connected
    def mkdir(self, dir_path: str, parent: bool = True) -> bool:
        """创建远程目录

        Args:
            dir_path: 要创建的远程目录路径
            parent: 是否递归创建父目录，默认 True

        Returns:
            bool: 创建成功返回True，失败返回False
        """
        try:
            # 如果路径为空，直接返回
            if not dir_path or dir_path in (".", "/"):
                logger.debug("无需创建根目录")
                return True

            with self._get_sftp() as sftp:
                if parent:
                    # 递归创建模式（类似 mkdir -p）
                    # 收集需要创建的目录列表
                    dirs_to_create = []
                    current_path = dir_path

                    # 从目标路径向上遍历，找出所有不存在的目录
                    while current_path and current_path != "/":
                        try:
                            sftp.stat(current_path)
                            # 如果目录存在，停止向上查找
                            break
                        except FileNotFoundError:
                            # 目录不存在，添加到待创建列表
                            dirs_to_create.append(current_path)
                            # 获取父目录
                            parent_dir = current_path.rsplit("/", 1)[0]
                            current_path = parent_dir if parent_dir else "/"

                    # 如果没有目录需要创建
                    if not dirs_to_create:
                        logger.debug(f"目录已存在: {dir_path}")
                        return True

                    # 从最上层目录开始逐层创建
                    created_dirs = []
                    for directory in reversed(dirs_to_create):
                        try:
                            sftp.mkdir(directory)
                            created_dirs.append(directory)
                            logger.debug(f"创建远程目录: {directory}")
                        except FileExistsError:
                            # 目录已存在（可能被其他进程创建），继续
                            logger.debug(f"目录已存在，跳过: {directory}")
                            continue
                        except Exception as e:
                            logger.error(f"创建目录失败: {directory}, 错误: {e}")
                            return False

                    logger.debug(f"递归创建目录成功: {dir_path} (创建了 {len(created_dirs)} 个目录)")
                    return True

                else:
                    # 单层创建模式（不创建父目录）
                    try:
                        sftp.mkdir(dir_path)
                        logger.debug(f"目录创建成功: {dir_path}")
                        return True
                    except FileExistsError:
                        logger.debug(f"目录已存在: {dir_path}")
                        return True
                    except Exception as e:
                        logger.error(f"创建目录失败: {dir_path}, 错误: {e}")
                        return False

        except Exception as e:
            logger.error(f"创建目录失败: {dir_path}, 错误: {e}")
            return False

    @ensure_connected
    def remove_file(self, remote_path: str) -> bool:
        """删除远程文件（若不存在则视为成功）

        Args:
            remote_path: 远程文件路径

        Returns:
            bool: 删除成功或文件不存在返回True，否则False
        """
        try:
            if not remote_path:
                logger.error("远程路径为空")
                raise ValueError("远程路径为空")

            with self._get_sftp() as sftp:
                try:
                    sftp.remove(remote_path)
                    logger.debug(f"删除远程文件成功: {remote_path}")
                except FileNotFoundError:
                    logger.debug(f"远程文件不存在（视为成功）: {remote_path}")
                return True

        except Exception as e:
            logger.error(f"删除远程文件失败: {remote_path}, 错误: {e}")
            return False

    @ensure_connected
    def remove_dir(self, dir_path: str) -> bool:
        """递归删除远程目录（不存在则视为成功）

        Args:
            dir_path: 远程目录路径

        Returns:
            bool: 删除成功或目录不存在返回True，否则False
        """
        try:
            if not dir_path or dir_path in ("/", "."):
                logger.error("危险或空目录路径，拒绝删除")
                raise ValueError("目录路径非法")

            with self._get_sftp() as sftp:
                # 若不存在则视为成功
                try:
                    attrs = sftp.stat(dir_path)
                except FileNotFoundError:
                    logger.debug(f"远程目录不存在（视为成功）: {dir_path}")
                    return True

                # 必须是目录
                if not stat.S_ISDIR(attrs.st_mode):
                    logger.debug(f"目标不是目录: {dir_path}")
                    return False

                def _rmdir_recursive(path: str) -> None:
                    for entry in sftp.listdir_attr(path):
                        child = f"{path.rstrip('/')}/{entry.filename}"
                        if stat.S_ISDIR(entry.st_mode):
                            _rmdir_recursive(child)
                        else:
                            sftp.remove(child)
                    sftp.rmdir(path)

                _rmdir_recursive(dir_path)
                logger.debug(f"删除远程目录成功: {dir_path}")
                return True

        except Exception as e:
            logger.error(f"删除远程目录失败: {dir_path}, 错误: {e}")
            return False

    @ensure_connected
    def upload_file(self, local_path: str, remote_path: str, create_dirs: bool = True) -> bool:
        """上传本地文件到远程

        Args:
            local_path: 本地文件路径
            remote_path: 远程保存路径
            create_dirs: 是否在远端自动创建缺失目录

        Returns:
            bool: 上传成功返回True，失败返回False

        示例:
            - 本地(Linux) → 远程: local_path='/home/user/a.txt', remote_path='/tmp/a.txt'
            - 本地(Windows) → 远程: local_path='C:\\Users\\user\\a.txt', remote_path='/tmp/a.txt'
        """
        try:
            if not local_path or not remote_path:
                logger.error("本地或远程路径为空")
                raise ValueError("本地或远程路径为空")

            if create_dirs and "/" in remote_path:
                remote_dir = remote_path.rsplit("/", 1)[0]
                if remote_dir and remote_dir != "/":
                    if not self.mkdir(remote_dir, parent=True):
                        logger.debug(f"创建远程目录失败: {remote_dir}")
                        return False

            with self._get_sftp() as sftp:
                sftp.put(local_path, remote_path)
                logger.debug(f"上传文件成功: {local_path} -> {remote_path}")
                return True

        except FileNotFoundError:
            logger.error(f"本地文件不存在: {local_path}")
            raise

        except Exception as e:
            logger.error(f"上传文件失败: {local_path} -> {remote_path}, 错误: {e}")
            return False

    @ensure_connected
    def download_file(self, remote_path: str, local_path: str, create_dirs: bool = True) -> bool:
        """从远程下载文件到本地

        Args:
            remote_path: 远程文件路径
            local_path: 本地保存路径
            create_dirs: 是否自动创建本地缺失目录

        Returns:
            bool: 下载成功返回True，失败返回False

        示例:
            - 远程 → 本地(Linux): remote_path='/tmp/a.txt', local_path='/home/user/a.txt'
            - 远程 → 本地(Windows): remote_path='/tmp/a.txt', local_path='C:\\Users\\user\\a.txt'
        """
        try:
            if not remote_path or not local_path:
                logger.error("本地或远程路径为空")
                raise ValueError("本地或远程路径为空")

            if create_dirs:
                local_dir = os.path.dirname(local_path)
                if local_dir:
                    try:
                        os.makedirs(local_dir, exist_ok=True)
                    except Exception as e:
                        logger.error(f"创建本地目录失败: {local_dir}, 错误: {e}")
                        return False

            with self._get_sftp() as sftp:
                sftp.get(remote_path, local_path)
                logger.debug(f"下载文件成功: {remote_path} -> {local_path}")
                return True

        except FileNotFoundError:
            logger.error(f"远程文件不存在: {remote_path}")
            return False

        except Exception as e:
            logger.error(f"下载文件失败: {remote_path} -> {local_path}, 错误: {e}")
            return False

    @ensure_connected
    def upload_dir(self, local_dir: str, remote_dir: str, create_dirs: bool = True) -> bool:
        """上传本地目录到远程目录（递归）

        Args:
            local_dir: 本地目录路径
            remote_dir: 远程目标目录
            create_dirs: 是否在远端自动创建缺失目录

        Returns:
            bool: 上传成功返回True，失败返回False

        示例:
            - 本地(Linux) → 远程: local_dir='/home/user/logs', remote_dir='/opt/app/logs'
            - 本地(Windows) → 远程: local_dir='C:\\Users\\user\\logs', remote_dir='/opt/app/logs'
        """
        try:
            if not local_dir or not remote_dir:
                logger.error("本地或远程路径为空")
                raise ValueError("本地或远程路径为空")

            if not os.path.isdir(local_dir):
                logger.error(f"本地目录不存在: {local_dir}")
                raise FileNotFoundError(f"本地目录不存在: {local_dir}")

            base_remote = remote_dir if remote_dir == "/" else remote_dir.rstrip("/")

            with self._get_sftp() as sftp:
                if create_dirs:
                    if not self.mkdir(base_remote, parent=True):
                        logger.debug(f"创建远程目录失败: {base_remote}")
                        return False

                for root, dirs, files in os.walk(local_dir):
                    rel = os.path.relpath(root, local_dir)
                    rel = "" if rel == "." else rel.replace("\\", "/")
                    current_remote = base_remote if not rel else f"{base_remote}/{rel}"

                    if create_dirs:
                        if not self.mkdir(current_remote, parent=True):
                            logger.debug(f"创建远程目录失败: {current_remote}")
                            return False

                    for name in files:
                        local_path = os.path.join(root, name)
                        remote_path = f"{current_remote}/{name}"
                        sftp.put(local_path, remote_path)

                logger.debug(f"上传目录成功: {local_dir} -> {remote_dir}")
                return True

        except FileNotFoundError:
            logger.error(f"本地目录不存在: {local_dir}")
            raise

        except Exception as e:
            logger.error(f"上传目录失败: {local_dir} -> {remote_dir}, 错误: {e}")
            return False

    @ensure_connected
    def download_dir(self, remote_dir: str, local_dir: str, create_dirs: bool = True) -> bool:
        """从远程目录下载到本地目录（递归）

        Args:
            remote_dir: 远程目录路径
            local_dir: 本地目标目录
            create_dirs: 是否自动创建本地缺失目录

        Returns:
            bool: 下载成功返回True，失败返回False

        示例:
            - 远程 → 本地(Linux): remote_dir='/opt/app/logs', local_dir='/home/user/logs'
            - 远程 → 本地(Windows): remote_dir='/opt/app/logs', local_dir='C:\\Users\\user\\logs'
        """
        try:
            if not remote_dir or not local_dir:
                logger.error("本地或远程路径为空")
                raise ValueError("本地或远程路径为空")

            if create_dirs:
                try:
                    os.makedirs(local_dir, exist_ok=True)
                except Exception as e:
                    logger.error(f"创建本地目录失败: {local_dir}, 错误: {e}")
                    return False

            with self._get_sftp() as sftp:
                try:
                    attrs = sftp.stat(remote_dir)
                except FileNotFoundError:
                    logger.error(f"远程目录不存在: {remote_dir}")
                    return False

                if not stat.S_ISDIR(attrs.st_mode):
                    logger.debug(f"目标不是目录: {remote_dir}")
                    return False

                def _download_recursive(rdir: str, ldir: str) -> None:
                    if create_dirs:
                        os.makedirs(ldir, exist_ok=True)
                    for entry in sftp.listdir_attr(rdir):
                        rchild = f"{rdir.rstrip('/')}/{entry.filename}"
                        lchild = os.path.join(ldir, entry.filename)
                        if stat.S_ISDIR(entry.st_mode):
                            _download_recursive(rchild, lchild)
                        else:
                            sftp.get(rchild, lchild)

                _download_recursive(remote_dir, local_dir)
                logger.debug(f"下载目录成功: {remote_dir} -> {local_dir}")
                return True

        except FileNotFoundError:
            logger.error(f"远程目录不存在: {remote_dir}")
            return False

        except Exception as e:
            logger.error(f"下载目录失败: {remote_dir} -> {local_dir}, 错误: {e}")
            return False

    @ensure_connected
    def chmod(self, remote_path: str, mode: int) -> bool:
        """设置远程路径权限

        Args:
            remote_path: 远程文件或目录路径
            mode: 权限位（如 0o644, 0o755）

        Returns:
            bool: 设置成功返回True，失败返回False
        """
        try:
            if not remote_path:
                logger.error("远程路径为空")
                raise ValueError("远程路径为空")

            with self._get_sftp() as sftp:
                sftp.chmod(remote_path, mode)
                logger.debug(f"设置权限成功: {remote_path} -> {oct(mode)}")
                return True

        except FileNotFoundError:
            logger.error(f"远程路径不存在: {remote_path}")
            return False

        except Exception as e:
            logger.error(f"设置权限失败: {remote_path} -> {oct(mode)}, 错误: {e}")
            return False

    @ensure_connected
    def rename(self, src_path: str, dst_path: str) -> bool:
        """重命名/移动远程路径

        Args:
            src_path: 源路径（文件或目录）
            dst_path: 目标路径（文件或目录）

        Returns:
            bool: 成功返回True，失败返回False
        """
        try:
            if not src_path or not dst_path:
                logger.error("源或目标路径为空")
                raise ValueError("源或目标路径为空")

            with self._get_sftp() as sftp:
                sftp.rename(src_path, dst_path)
                logger.debug(f"重命名/移动成功: {src_path} -> {dst_path}")
                return True

        except FileNotFoundError:
            logger.error(f"源路径不存在: {src_path}")
            return False

        except Exception as e:
            logger.error(f"重命名/移动失败: {src_path} -> {dst_path}, 错误: {e}")
            return False

    @ensure_connected
    def get_info(self, remote_path: str) -> tuple[bool, dict[str, Any]]:
        """获取远程文件/目录信息

        Args:
            remote_path: 远程路径

        Returns:
            tuple[bool, dict]:
                - True, {详细信息}
                - False, {"error": 错误信息}

        信息字段包括：path, type, is_file, is_dir, size, mode, uid, gid, atime, mtime
        """
        try:
            if not remote_path:
                logger.error("远程路径为空")
                raise ValueError("远程路径为空")

            with self._get_sftp() as sftp:
                attrs = sftp.stat(remote_path)
                file_mode = attrs.st_mode
                is_file = stat.S_ISREG(file_mode)
                is_dir = stat.S_ISDIR(file_mode)
                file_type = "file" if is_file else ("dir" if is_dir else "other")

                info: dict[str, Any] = {
                    "path": remote_path,
                    "type": file_type,
                    "is_file": is_file,
                    "is_dir": is_dir,
                    "size": getattr(attrs, "st_size", None),
                    "mode": oct(file_mode) if isinstance(file_mode, int) else None,
                    "uid": getattr(attrs, "st_uid", None),
                    "gid": getattr(attrs, "st_gid", None),
                    "atime": getattr(attrs, "st_atime", None),
                    "mtime": getattr(attrs, "st_mtime", None),
                }

                logger.debug(f"获取信息成功: {remote_path} -> {info}")
                return True, info

        except FileNotFoundError:
            logger.error(f"远程路径不存在: {remote_path}")
            return False, {"error": "not found"}

        except Exception as e:
            logger.error(f"获取信息失败: {remote_path}, 错误: {e}")
            return False, {"error": str(e)}


if __name__ == "__main__":
    ip = "192.168.56.102"
    port = 22
    username = "root"
    password = "root"

    ssh_tool = SSHTool(ip=ip, port=port, username=username, password=password)

    # connect 方法
    flag = ssh_tool.connect()
    assert flag == True, "connect fail"

    # is_connected 方法
    flag = ssh_tool.is_connected()
    assert flag == True, "is_connected fail"

    flag, output = ssh_tool.run_cmd("whoami")
    assert flag == True and output == "root", "run_cmd fail"

    # file_exists 方法
    flag = ssh_tool.file_exists("/etc/yum.repos.d/centos.repo")
    assert flag == True, "file_exists fail"

    flag = ssh_tool.file_exists("/tmp/not_exist_file.txt")
    assert flag == False, "file_exists fail"

    # dir_exists 方法
    flag = ssh_tool.dir_exists("/home")
    assert flag == True, "dir_exists fail"

    flag = ssh_tool.dir_exists("/tmp/not_exist_dir")
    assert flag == False, "dir_exists fail"

    # path_exists 方法
    flag = ssh_tool.path_exists("/etc/yum.repos.d/centos.repo")
    assert flag == True, "path_exists fail"

    flag = ssh_tool.path_exists("/home")
    assert flag == True, "path_exists fail"

    flag = ssh_tool.path_exists("/not/exist/path")
    assert flag == False, "path_exists fail"

    # mkdir 方法
    flag = ssh_tool.mkdir("/tmp/test_single_dir", parent=False)
    assert flag == True, "mkdir fail"

    flag = ssh_tool.mkdir("/tmp/test_mkdir_p/level1/level2")
    assert flag == True, "mkdir fail"

    time.sleep(10)

    # 清理
    ssh_tool.remove_dir("/tmp/test_single_dir")
    ssh_tool.remove_dir("/tmp/test_mkdir_p")

    sys.exit(0)

    base_remote = "/tmp/ddr_test"
    ssh_tool.remove_dir(base_remote)  # 预清理
    assert ssh_tool.mkdir(base_remote, parent=True) == True, "prepare base_remote fail"

    # 1) upload_file / chmod / get_info / rename / download_file
    tmpdir = tempfile.mkdtemp(prefix="ssh_tool_")
    local_file = os.path.join(tmpdir, "test_upload.txt")
    with open(local_file, "w", encoding="utf-8") as f:
        f.write("hello-ssh-tool\n")

    remote_file = f"{base_remote}/test_upload.txt"
    assert ssh_tool.upload_file(local_file, remote_file, create_dirs=True) == True, "upload_file fail"
    assert ssh_tool.file_exists(remote_file) == True, "remote uploaded file not exists"

    assert ssh_tool.chmod(remote_file, 0o644) == True, "chmod fail"
    ok, info = ssh_tool.get_info(remote_file)
    assert ok and info.get("is_file") and str(info.get("mode", "")).endswith("644"), "get_info fail or mode mismatch"

    remote_file2 = f"{base_remote}/test_upload_renamed.txt"
    assert ssh_tool.rename(remote_file, remote_file2) == True, "rename fail"
    assert (
        ssh_tool.file_exists(remote_file2) == True and ssh_tool.file_exists(remote_file) == False
    ), "rename result check fail"

    local_download = os.path.join(tmpdir, "test_download.txt")
    assert ssh_tool.download_file(remote_file2, local_download, create_dirs=True) == True, "download_file fail"
    with open(local_download, "r", encoding="utf-8") as f:
        assert "hello-ssh-tool" in f.read(), "downloaded content mismatch"

    # 2) upload_dir / download_dir
    local_dir_to_upload = os.path.join(tmpdir, "dir_a")
    os.makedirs(local_dir_to_upload, exist_ok=True)
    with open(os.path.join(local_dir_to_upload, "a1.txt"), "w", encoding="utf-8") as f:
        f.write("file-a1\n")
    nested = os.path.join(local_dir_to_upload, "nested")
    os.makedirs(nested, exist_ok=True)
    with open(os.path.join(nested, "n1.txt"), "w", encoding="utf-8") as f:
        f.write("nested-n1\n")

    remote_dir_target = f"{base_remote}/dir_a"
    assert ssh_tool.upload_dir(local_dir_to_upload, remote_dir_target, create_dirs=True) == True, "upload_dir fail"
    assert ssh_tool.dir_exists(remote_dir_target) == True, "remote dir not exists after upload_dir"
    assert ssh_tool.file_exists(f"{remote_dir_target}/a1.txt") == True, "uploaded file missing"

    local_dir_download = os.path.join(tmpdir, "dir_download")
    assert ssh_tool.download_dir(remote_dir_target, local_dir_download, create_dirs=True) == True, "download_dir fail"
    assert os.path.isfile(os.path.join(local_dir_download, "a1.txt")), "downloaded file missing"

    # 3) remove_file / remove_dir
    assert ssh_tool.remove_file(remote_file2) == True, "remove_file fail"
    assert ssh_tool.file_exists(remote_file2) == False, "remote file still exists after remove"

    assert ssh_tool.remove_dir(base_remote) == True, "remove_dir fail"
    assert ssh_tool.dir_exists(base_remote) == False, "remote dir still exists after remove"

    # 本地清理
    shutil.rmtree(tmpdir, ignore_errors=True)
