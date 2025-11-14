import json
import os
import tempfile
import time
from datetime import datetime

import requests
from loguru import logger

from sk_lib.network import SSHTool
from sk_lib.public.enums import OsPlatform


class LinuxEnv:
    """当前只支持centos操作系统"""

    def __init__(self, os_platform: OsPlatform, ip: str, username: str, password: str, port: int = 22):
        self.ssh_tool = SSHTool(ip, port, username, password)
        if os_platform != OsPlatform.Centos:
            raise ValueError(f"当前仅支持Centos操作系统")

    def _wrap_cmd_with_pty(self, cmd: str) -> str:
        """使用 script 伪造 PTY，强制 yum 输出进度条"""
        # 转义单引号，防止命令注入（简单处理）
        safe_cmd = cmd.replace("'", "'\"'\"'")
        return f"script -qec '{safe_cmd}' /dev/null"

    def install_development_tools(self) -> bool:
        """安装 Development Tools 编译工具组（包含 gcc、make、glibc-devel 等编译依赖）

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info("安装 Development Tools 编译工具组...")
        group_install_cmd = "yum groupinstall -y 'Development Tools'"
        group_install_cmd_stream = self._wrap_cmd_with_pty(group_install_cmd)
        success, output = self.ssh_tool.run_cmd(group_install_cmd_stream, realtime_output=True)
        if not success:
            logger.error(f"Development Tools 组安装失败: {output}")
            return False

        # 验证是否真正安装成功（检查关键编译工具是否存在）
        logger.info("验证编译工具是否安装成功...")
        key_tools = ["gcc", "make"]
        missing_tools = []

        for tool in key_tools:
            check_cmd = f"which {tool} && echo 'exists' || echo 'not_exists'"
            check_success, check_output = self.ssh_tool.run_cmd(check_cmd)
            # 检查输出的最后一行是否是 "exists"（因为 which 命令会输出路径）
            output_lines = check_output.strip().split("\n")
            last_line = output_lines[-1].strip() if output_lines else ""
            if not check_success or last_line != "exists":
                missing_tools.append(tool)

        if missing_tools:
            logger.error(f"Development Tools 组安装失败：以下工具未找到 {missing_tools}")
            return False

        logger.info("Development Tools 组安装成功（gcc 和 make 已可用）")
        return True

    def base_install(self) -> bool:
        """基础环境安装
        包括：EPEL 仓库、Git、Development Tools 编译工具组，以及系统更新

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info("开始基础环境安装...")

        if not self.clean_yum_process():
            return False

        # 安装 EPEL 仓库（推荐，提供更多软件包）
        logger.info("安装 EPEL 仓库...")
        if not self.install_soft("epel-release"):
            logger.error("EPEL 仓库安装失败")
            return False

        # 更新系统包
        logger.info("更新系统包...")
        if not self.yum_update():
            logger.error("系统包更新失败")
            return False

        # 安装常见工具
        logger.info("安装常见工具...")
        common_tools = ["wget", "vim", "curl", "gzip", "tar"]
        for tool in common_tools:
            logger.info(f"安装 {tool}...")
            if not self.install_soft(tool):
                logger.error(f"{tool} 安装失败")

        # 安装 Development Tools 组
        if not self.install_development_tools():
            return False

        logger.info("基础环境安装完成")
        return True

    def reboot(self) -> bool:
        """重启系统"""
        success, output = self.ssh_tool.run_cmd("reboot")
        if success:
            return self.check_reboot_ok()
        else:
            logger.error(f"Reboot system error: {output}")
            return False

    def check_reboot_ok(self, max_wait_time: int = 300, retry_interval: int = 5) -> bool:
        """检查重启是否完成

        Args:
            max_wait_time: 最大等待时间（秒），默认300秒（5分钟）
            retry_interval: 重试间隔（秒），默认5秒

        Returns:
            bool: 如果重启完成并成功连接返回True，否则返回False
        """
        # 先断开当前连接（服务器正在重启）
        self.ssh_tool.disconnect()
        logger.info("等待服务器重启完成...")
        logger.info(f"最大等待时间: {max_wait_time} 秒")
        logger.info(f"重试间隔: {retry_interval} 秒")

        start_time = time.time()
        time.sleep(5)
        attempt = 0

        while time.time() - start_time < max_wait_time:
            attempt += 1
            logger.info(f"尝试连接服务器 (第 {attempt} 次)...")

            # 尝试重新连接
            if self.ssh_tool.connect(timeout=5):
                logger.info(f"服务器重启完成，SSH连接成功 (耗时: {int(time.time() - start_time)} 秒)")
                return True

            # 等待后重试
            if time.time() - start_time < max_wait_time:
                logger.debug(f"连接失败，{retry_interval} 秒后重试...")
                time.sleep(retry_interval)

        logger.error(f"等待服务器重启超时 (超过 {max_wait_time} 秒)")
        return False

    def kill_process_by_name(self, process_name: str, force: bool = False, case_sensitive: bool = True) -> bool:
        """根据进程名杀死进程

        Args:
            process_name: 进程名称
            force: 是否强制杀死（使用 SIGKILL 信号），默认 False（使用 SIGTERM）
            case_sensitive: 是否区分大小写，默认 True（区分大小写）

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        # 构建 killall 命令
        cmd_parts = ["killall"]

        # 如果强制杀死，使用 -9 信号
        if force:
            cmd_parts.append("-9")

        # 如果不区分大小写，添加 -I 参数
        if not case_sensitive:
            cmd_parts.append("-I")

        cmd_parts.append(process_name)

        cmd = " ".join(cmd_parts)
        logger.info(f"执行命令: {cmd}")

        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            logger.info(f"成功杀死进程: {process_name}")
            return True
        else:
            # killall 在找不到进程时会返回非零退出码，但不一定是错误
            # 检查输出中是否包含 "no process found" 或类似信息
            output_lower = output.lower()
            if "no process found" in output_lower or "no such process" in output_lower:
                logger.warning(f"未找到进程: {process_name}")
                return False
            else:
                logger.error(f"杀死进程失败: {process_name}, 错误: {output}")
                return False

    def kill_process_by_pid(self, process_id: int, force: bool = False) -> bool:
        """根据进程ID杀死进程

        Args:
            process_id: 进程ID（PID）
            force: 是否强制杀死（使用 SIGKILL 信号），默认 False（使用 SIGTERM）

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        # 构建 kill 命令
        if force:
            signal = "-9"
        else:
            signal = "-15"  # SIGTERM，默认信号

        cmd = f"kill {signal} {process_id}"
        logger.info(f"执行命令: {cmd}")

        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            logger.info(f"成功杀死进程: PID {process_id}")
            return True
        else:
            # kill 命令在找不到进程时会返回非零退出码
            output_lower = output.lower()
            if "no such process" in output_lower or "invalid argument" in output_lower:
                logger.warning(f"未找到进程: PID {process_id}")
                return False
            else:
                logger.error(f"杀死进程失败: PID {process_id}, 错误: {output}")
                return False

    def kill_process_by_pids(self, process_ids: list[int], force: bool = False) -> dict[int, bool]:
        """根据进程ID列表批量杀死进程

        Args:
            process_ids: 进程ID列表
            force: 是否强制杀死（使用 SIGKILL 信号），默认 False（使用 SIGTERM）

        Returns:
            dict[int, bool]: 返回每个进程ID和对应的执行结果，True表示成功，False表示失败
        """
        if not process_ids:
            logger.warning("进程ID列表为空")
            return {}

        # 构建 kill 命令，可以一次性杀死多个进程
        if force:
            signal = "-9"
        else:
            signal = "-15"  # SIGTERM，默认信号

        # 将所有PID转换为字符串并拼接
        pids_str = " ".join(str(pid) for pid in process_ids)
        cmd = f"kill {signal} {pids_str}"
        logger.info(f"执行命令: {cmd}")

        success, output = self.ssh_tool.run_cmd(cmd)

        # 初始化结果字典，默认都设为成功
        results = {pid: True for pid in process_ids}

        if success:
            logger.info(f"成功杀死进程: PIDs {process_ids}")
            return results
        else:
            # kill 命令在部分进程不存在时仍可能返回非零退出码
            # 需要检查哪些进程确实被杀死了
            output_lower = output.lower()

            # 如果输出中包含 "no such process"，说明有些进程不存在
            # 但 kill 命令会尝试杀死所有进程，已存在的进程会被杀死
            # 为了更准确地判断，我们可以逐个检查进程是否还存在
            # 或者直接返回结果，因为 kill 命令会尽力杀死所有存在的进程

            # 检查输出中是否有错误信息
            if "no such process" in output_lower or "invalid argument" in output_lower:
                # 对于不存在的进程，标记为失败
                # 但由于 kill 命令的输出可能不够详细，我们采用保守策略
                # 如果命令失败，我们逐个检查进程是否还存在
                logger.warning(f"部分进程可能不存在，正在验证...")

                # 逐个检查进程是否还存在
                for pid in process_ids:
                    # 使用 ps 命令检查进程是否存在
                    check_cmd = f"ps -p {pid} > /dev/null 2>&1"
                    check_success, _ = self.ssh_tool.run_cmd(check_cmd)
                    # 如果进程不存在（ps 返回非零），说明已经被杀死或本来就不存在
                    # 如果进程还存在（ps 返回成功），说明杀死失败
                    results[pid] = not check_success

                # 统计结果
                success_count = sum(1 for v in results.values() if v)
                logger.info(f"批量杀死进程完成: 成功 {success_count}/{len(process_ids)}")
            else:
                # 其他错误，标记所有为失败
                logger.error(f"杀死进程失败: PIDs {process_ids}, 错误: {output}")
                results = {pid: False for pid in process_ids}

            return results

    def get_pids_by_name(self, process_name: str, case_sensitive: bool = True) -> list[int]:
        """根据进程名获取进程ID列表

        Args:
            process_name: 进程名称
            case_sensitive: 是否区分大小写，默认 True（区分大小写）

        Returns:
            list[int]: 进程ID列表，如果未找到进程则返回空列表
        """
        # 构建 pgrep 命令
        cmd_parts = ["pgrep"]

        # 如果不区分大小写，添加 -i 参数
        if not case_sensitive:
            cmd_parts.append("-i")

        # 使用 -f 参数可以匹配完整命令行，但这里只匹配进程名
        # 直接使用进程名，pgrep 默认匹配进程名
        cmd_parts.append(process_name)

        cmd = " ".join(cmd_parts)
        logger.debug(f"执行命令: {cmd}")

        success, output = self.ssh_tool.run_cmd(cmd)

        if success and output.strip():
            # 解析输出，获取所有PID
            pids = []
            for line in output.strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        pid = int(line)
                        pids.append(pid)
                    except ValueError:
                        logger.warning(f"无法解析PID: {line}")
                        continue

            logger.info(f"找到进程 {process_name} 的PID: {pids}")
            return pids
        else:
            # pgrep 在找不到进程时返回非零退出码，这是正常情况
            logger.debug(f"未找到进程: {process_name}")
            return []

    def get_open_ports_info(self) -> list[dict[str, str | int]]:
        """获取所有已开放的端口

        Returns:
            list[dict]: 端口信息列表，每个字典包含以下字段：
                - port: 端口号 (int)
                - protocol: 协议类型，'tcp' 或 'udp' (str)
                - state: 连接状态，如 'LISTEN', 'ESTABLISHED' 等 (str)
                - local_address: 本地地址 (str)
                - foreign_address: 远程地址（如果有）(str)
        """
        ports_info = []

        # 优先使用 ss 命令（更现代、更快）
        # ss -tuln 显示所有监听的TCP和UDP端口
        # -t: TCP
        # -u: UDP
        # -l: 只显示监听状态的端口
        # -n: 以数字形式显示地址和端口
        cmd = "ss -tuln"
        logger.debug(f"执行命令: {cmd}")

        success, output = self.ssh_tool.run_cmd(cmd)

        if success and output.strip():
            # 解析 ss 命令输出
            # 格式示例：
            # Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
            # tcp   LISTEN 0      128    0.0.0.0:22        0.0.0.0:*
            lines = output.strip().split("\n")

            for line in lines[1:]:  # 跳过标题行
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                if len(parts) < 5:
                    continue

                try:
                    protocol = parts[0].lower()  # tcp, udp, tcp6, udp6
                    state = parts[1]
                    local_addr_port = parts[4]

                    # 解析本地地址和端口
                    if ":" in local_addr_port:
                        local_address, port_str = local_addr_port.rsplit(":", 1)
                        # 处理 IPv6 地址（可能包含多个冒号）
                        if local_addr_port.count(":") > 1 and not local_addr_port.startswith("::"):
                            # IPv6 地址，找到最后一个冒号
                            last_colon = local_addr_port.rfind(":")
                            local_address = local_addr_port[:last_colon]
                            port_str = local_addr_port[last_colon + 1 :]

                        try:
                            port = int(port_str)

                            # 解析远程地址（如果有）
                            foreign_address = ""
                            if len(parts) > 5:
                                foreign_address = parts[5]

                            port_info = {
                                "port": port,
                                "protocol": protocol.replace("6", ""),  # tcp6 -> tcp, udp6 -> udp
                                "state": state,
                                "local_address": local_address,
                                "foreign_address": foreign_address if foreign_address else "",
                            }
                            ports_info.append(port_info)
                        except ValueError:
                            logger.warning(f"无法解析端口号: {port_str}")
                            continue
                except (IndexError, ValueError) as e:
                    logger.warning(f"解析端口信息失败: {line}, 错误: {e}")
                    continue

        # 如果 ss 命令失败，尝试使用 netstat 作为备选
        if not success or not ports_info:
            logger.debug("ss 命令失败或未找到端口，尝试使用 netstat...")
            cmd = "netstat -tuln"
            success, output = self.ssh_tool.run_cmd(cmd)

            if success and output.strip():
                lines = output.strip().split("\n")

                for line in lines[2:]:  # 跳过标题行
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) < 4:
                        continue

                    try:
                        protocol = parts[0].lower()
                        if protocol not in ["tcp", "udp", "tcp6", "udp6"]:
                            continue

                        local_addr_port = parts[3]

                        # 解析本地地址和端口
                        if ":" in local_addr_port:
                            local_address, port_str = local_addr_port.rsplit(":", 1)

                            # 处理 IPv6
                            if local_addr_port.count(":") > 1 and not local_addr_port.startswith("::"):
                                last_colon = local_addr_port.rfind(":")
                                local_address = local_addr_port[:last_colon]
                                port_str = local_addr_port[last_colon + 1 :]

                            try:
                                port = int(port_str)

                                state = ""
                                foreign_address = ""
                                if len(parts) > 4:
                                    if protocol.startswith("tcp"):
                                        state = parts[5] if len(parts) > 5 else ""
                                        foreign_address = parts[4] if len(parts) > 4 else ""
                                    else:
                                        foreign_address = parts[4] if len(parts) > 4 else ""

                                port_info = {
                                    "port": port,
                                    "protocol": protocol.replace("6", ""),
                                    "state": state,
                                    "local_address": local_address,
                                    "foreign_address": foreign_address if foreign_address else "",
                                }
                                ports_info.append(port_info)
                            except ValueError:
                                logger.warning(f"无法解析端口号: {port_str}")
                                continue
                    except (IndexError, ValueError) as e:
                        logger.warning(f"解析端口信息失败: {line}, 错误: {e}")
                        continue

        # 去重（同一个端口可能同时监听 IPv4 和 IPv6）
        seen_ports = set()
        unique_ports_info = []
        for port_info in ports_info:
            key = (port_info["port"], port_info["protocol"])
            if key not in seen_ports:
                seen_ports.add(key)
                unique_ports_info.append(port_info)

        logger.info(f"找到 {len(unique_ports_info)} 个开放的端口")
        logger.info(f"端口信息：\n{json.dumps(unique_ports_info, indent=2)}")
        return unique_ports_info

    def get_process_list(self) -> list[dict[str, str | int | float]]:
        """获取进程列表

        Returns:
            list[dict]: 进程信息列表，每个字典包含以下字段：
                - pid: 进程ID (int)
                - name: 进程名称 (str)
                - cpu_percent: CPU使用率百分比 (float)
                - mem_percent: 内存使用率百分比 (float)
                - user: 运行用户 (str)
                - vsz: 虚拟内存大小，单位KB (int)
                - rss: 物理内存大小，单位KB (int)
                - stat: 进程状态 (str)
                - start: 启动时间 (str)
                - time: CPU时间 (str)
                - command: 完整命令 (str)
        """
        process_list = []

        # 使用 ps 命令获取进程信息
        # ps aux 显示所有进程的详细信息
        # 或者使用 ps -eo 指定格式
        cmd = "ps aux"
        logger.debug(f"执行命令: {cmd}")

        success, output = self.ssh_tool.run_cmd(cmd)

        if success and output.strip():
            lines = output.strip().split("\n")

            for line in lines[1:]:  # 跳过标题行
                line = line.strip()
                if not line:
                    continue

                # ps aux 输出格式：
                # USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
                # root         1  0.0  0.1  12345  1234 ?        Ss   Jan01   0:01 /sbin/init
                parts = line.split(None, 10)  # 最多分割10次，保留命令部分

                if len(parts) < 11:
                    # 如果命令部分为空或格式不标准，尝试其他解析方式
                    continue

                try:
                    user = parts[0]
                    pid = int(parts[1])
                    cpu_percent = float(parts[2])
                    mem_percent = float(parts[3])
                    vsz = int(parts[4]) if parts[4].isdigit() else 0
                    rss = int(parts[5]) if parts[5].isdigit() else 0
                    tty = parts[6]
                    stat = parts[7]
                    start = parts[8]
                    time = parts[9]
                    command = parts[10] if len(parts) > 10 else ""

                    # 提取进程名称（命令的第一部分）
                    process_name = command.split()[0] if command else ""
                    # 去掉路径，只保留文件名
                    if "/" in process_name:
                        process_name = process_name.split("/")[-1]

                    process_info = {
                        "pid": pid,
                        "name": process_name,
                        "cpu_percent": cpu_percent,
                        "mem_percent": mem_percent,
                        "user": user,
                        "vsz": vsz,
                        "rss": rss,
                        "stat": stat,
                        "start": start,
                        "time": time,
                        "command": command,
                    }
                    process_list.append(process_info)
                except (ValueError, IndexError) as e:
                    logger.warning(f"解析进程信息失败: {line}, 错误: {e}")
                    continue

        logger.info(f"获取到 {len(process_list)} 个进程")
        return process_list

    def open_port(self, port: int, protocol: str = "tcp") -> bool:
        """开放端口

        Args:
            port: 端口号
            protocol: 协议类型，'tcp' 或 'udp'，默认 'tcp'

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        protocol = protocol.lower()
        if protocol not in ["tcp", "udp"]:
            logger.error(f"不支持的协议类型: {protocol}，仅支持 'tcp' 或 'udp'")
            return False

        # 优先使用 firewalld（CentOS 7+ 默认）
        # 检查 firewalld 是否运行
        success, output = self.ssh_tool.run_cmd("systemctl is-active firewalld")
        if success and output.strip() == "active":
            # 使用 firewalld 开放端口
            cmd = f"firewall-cmd --permanent --add-port={port}/{protocol}"
            logger.info(f"执行命令: {cmd}")
            success, output = self.ssh_tool.run_cmd(cmd)

            if success:
                # 重新加载防火墙配置
                reload_cmd = "firewall-cmd --reload"
                logger.debug(f"重新加载防火墙配置: {reload_cmd}")
                reload_success, reload_output = self.ssh_tool.run_cmd(reload_cmd)
                if reload_success:
                    logger.info(f"成功开放端口: {port}/{protocol}")
                    return True
                else:
                    logger.error(f"重新加载防火墙配置失败: {reload_output}")
                    return False
            else:
                logger.warning(f"firewalld 开放端口失败，尝试使用 iptables: {output}")

        # 使用 iptables 作为备选方案
        logger.debug("使用 iptables 开放端口...")
        # 检查端口是否已经开放
        check_cmd = f"iptables -C INPUT -p {protocol} --dport {port} -j ACCEPT 2>&1"
        check_success, _ = self.ssh_tool.run_cmd(check_cmd)

        if check_success:
            logger.info(f"端口 {port}/{protocol} 已经开放")
            return True

        # 添加 iptables 规则
        cmd = f"iptables -A INPUT -p {protocol} --dport {port} -j ACCEPT"
        logger.info(f"执行命令: {cmd}")
        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            # 保存 iptables 规则（根据不同的系统使用不同的命令）
            save_cmd = "iptables-save > /etc/sysconfig/iptables 2>&1 || service iptables save 2>&1 || true"
            self.ssh_tool.run_cmd(save_cmd)
            logger.info(f"成功开放端口: {port}/{protocol}")
            return True
        else:
            logger.error(f"开放端口失败: {port}/{protocol}, 错误: {output}")
            return False

    def close_port(self, port: int, protocol: str = "tcp") -> bool:
        """关闭端口

        Args:
            port: 端口号
            protocol: 协议类型，'tcp' 或 'udp'，默认 'tcp'

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        protocol = protocol.lower()
        if protocol not in ["tcp", "udp"]:
            logger.error(f"不支持的协议类型: {protocol}，仅支持 'tcp' 或 'udp'")
            return False

        # 优先使用 firewalld（CentOS 7+ 默认）
        # 检查 firewalld 是否运行
        success, output = self.ssh_tool.run_cmd("systemctl is-active firewalld")
        if success and output.strip() == "active":
            # 使用 firewalld 关闭端口
            cmd = f"firewall-cmd --permanent --remove-port={port}/{protocol}"
            logger.info(f"执行命令: {cmd}")
            success, output = self.ssh_tool.run_cmd(cmd)

            if success:
                # 重新加载防火墙配置
                reload_cmd = "firewall-cmd --reload"
                logger.debug(f"重新加载防火墙配置: {reload_cmd}")
                reload_success, reload_output = self.ssh_tool.run_cmd(reload_cmd)
                if reload_success:
                    logger.info(f"成功关闭端口: {port}/{protocol}")
                    return True
                else:
                    logger.error(f"重新加载防火墙配置失败: {reload_output}")
                    return False
            else:
                logger.warning(f"firewalld 关闭端口失败，尝试使用 iptables: {output}")

        # 使用 iptables 作为备选方案
        logger.debug("使用 iptables 关闭端口...")
        # 检查端口规则是否存在
        check_cmd = f"iptables -C INPUT -p {protocol} --dport {port} -j ACCEPT 2>&1"
        check_success, _ = self.ssh_tool.run_cmd(check_cmd)

        if not check_success:
            logger.info(f"端口 {port}/{protocol} 未开放或已关闭")
            return True

        # 删除 iptables 规则
        cmd = f"iptables -D INPUT -p {protocol} --dport {port} -j ACCEPT"
        logger.info(f"执行命令: {cmd}")
        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            # 保存 iptables 规则
            save_cmd = "iptables-save > /etc/sysconfig/iptables 2>&1 || service iptables save 2>&1 || true"
            self.ssh_tool.run_cmd(save_cmd)
            logger.info(f"成功关闭端口: {port}/{protocol}")
            return True
        else:
            logger.error(f"关闭端口失败: {port}/{protocol}, 错误: {output}")
            return False

    def firewall_status(self) -> str:
        """获取防火墙状态

        Returns:
            str: 防火墙状态，可能的值：
                - 'firewalld_active': firewalld 正在运行
                - 'firewalld_inactive': firewalld 已安装但未运行
                - 'iptables_active': iptables 正在运行或规则存在
                - 'iptables_inactive': iptables 已安装但未运行
                - 'ufw_active': ufw 正在运行（Ubuntu/Debian）
                - 'disabled': 防火墙未启用
        """
        # 优先检查 firewalld
        success, output = self.ssh_tool.run_cmd("systemctl is-active firewalld 2>&1")
        if success:
            status = output.strip()
            if status == "active":
                logger.debug("防火墙状态: firewalld 正在运行")
                return "firewalld_active"
            elif status == "inactive":
                # 检查 firewalld 是否已安装
                check_installed, _ = self.ssh_tool.run_cmd("systemctl list-unit-files | grep -q firewalld.service 2>&1")
                if check_installed:
                    logger.debug("防火墙状态: firewalld 已安装但未运行")
                    return "firewalld_inactive"

        # 检查 iptables 服务状态
        success, output = self.ssh_tool.run_cmd("systemctl is-active iptables 2>&1")
        if success:
            status = output.strip()
            if status == "active":
                logger.debug("防火墙状态: iptables 正在运行")
                return "iptables_active"
            elif status == "inactive":
                # 检查 iptables 是否已安装
                check_installed, _ = self.ssh_tool.run_cmd("which iptables 2>&1")
                if check_installed:
                    logger.debug("防火墙状态: iptables 已安装但未运行")
                    return "iptables_inactive"

        # 检查 iptables 规则是否存在（即使服务未运行，规则也可能存在）
        success, output = self.ssh_tool.run_cmd("iptables -L -n 2>&1 | head -5")
        if success and output.strip():
            # 检查是否有默认策略
            check_policy, policy_output = self.ssh_tool.run_cmd(
                "iptables -L INPUT -n --line-numbers 2>&1 | grep -i policy"
            )
            if check_policy and policy_output.strip():
                logger.debug("防火墙状态: iptables 规则存在")
                return "iptables_active"

        # 检查是否有其他防火墙工具
        # 检查 ufw (Ubuntu/Debian)
        success, output = self.ssh_tool.run_cmd("systemctl is-active ufw 2>&1")
        if success and output.strip() == "active":
            logger.debug("防火墙状态: ufw 正在运行")
            return "ufw_active"

        # 如果都没有找到，返回未启用
        logger.debug("防火墙状态: 未启用或无法确定")
        return "disabled"

    def install_soft(self, soft: str, version: str | None = None) -> bool:
        """安装软件

        Args:
            soft: 软件名称
            version: 软件版本号（可选），仅对 pyenv 和 nvm 等特殊软件有效

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        # 特殊软件使用专门的安装方法
        if soft == "pyenv":
            return self._install_pyenv(version=version)
        elif soft == "nvm":
            return self._install_nvm(version=version)

        return self._yum_install(soft)

    def uninstall_soft(self, soft: str) -> bool:
        """卸载软件

        Args:
            soft: 软件名称

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        # 特殊软件使用专门的卸载方法
        if soft == "pyenv":
            return self._uninstall_pyenv()
        elif soft == "nvm":
            return self._uninstall_nvm()

        return self._yum_uninstall(soft)

    def clean_yum_process(self) -> bool:
        """清理 yum 进程和锁文件
        检查并终止正在运行的 yum 进程，清理 yum 锁文件，避免 yum 操作冲突

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info("开始清理 yum 进程和锁文件...")

        # 检查并清理可能存在的 yum 进程
        logger.info("检查是否有其他 yum 进程正在运行...")
        pids = self.get_pids_by_name("yum", case_sensitive=False)
        if pids:
            logger.warning(f"发现正在运行的 yum 进程: {pids}，将强制终止...")
            results = self.kill_process_by_pids(pids, force=True)
            # 等待进程完全终止
            time.sleep(2)
            logger.info("已终止旧的 yum 进程")
        else:
            logger.info("未发现正在运行的 yum 进程")

        # 清理 yum 锁文件（如果存在）
        logger.info("清理 yum 锁文件...")
        lock_files = [
            "/var/run/yum.pid",
            "/var/lock/subsys/yum",
        ]
        for lock_file in lock_files:
            remove_cmd = f"rm -f {lock_file}"
            success, output = self.ssh_tool.run_cmd(remove_cmd)
            if not success:
                logger.warning(f"清理锁文件 {lock_file} 失败: {output}")
        logger.info("yum 锁文件清理完成")

        return True

    def backup_yum_repos(self, add_date: bool = True, backup_dir: str | None = None) -> bool:
        """备份 yum.repos.d 目录下的源文件

        Args:
            add_date: 是否在备份文件名中添加日期时间戳，默认 True
                     如果为 True，格式为：centos.repo.backup.2025_10_09_08_44_09
                     如果为 False，格式为：centos.repo.backup
            backup_dir: 备份目录路径，默认为 None（使用同级目录，即 /etc/yum.repos.d/）

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info("开始备份 yum.repos.d 目录下的源文件...")

        repo_dir = "/etc/yum.repos.d"
        # 如果未指定备份目录，使用同级目录
        if backup_dir is None:
            backup_dir = repo_dir
        else:
            # 确保备份目录存在
            logger.info(f"检查备份目录是否存在: {backup_dir}")
            mkdir_cmd = f"mkdir -p {backup_dir}"
            success, output = self.ssh_tool.run_cmd(mkdir_cmd)
            if not success:
                logger.error(f"创建备份目录失败: {output}")
                return False
            logger.info(f"备份目录已准备: {backup_dir}")

        repo_files = ["centos.repo", "centos-addons.repo"]

        # 生成日期时间戳（如果需要）
        date_suffix = ""
        if add_date:
            date_suffix = datetime.now().strftime(".%Y_%m_%d_%H_%M_%S")

        success_count = 0
        skipped_count = 0
        failed_count = 0

        for repo_file in repo_files:
            source_path = f"{repo_dir}/{repo_file}"
            backup_name = f"{repo_file}.backup{date_suffix}"
            backup_path = f"{backup_dir}/{backup_name}"

            # 检查源文件是否存在
            logger.info(f"检查源文件是否存在: {source_path}")
            check_cmd = f"test -f {source_path} && echo 'exists' || echo 'not_exists'"
            success, output = self.ssh_tool.run_cmd(check_cmd)
            if not success or output.strip() != "exists":
                logger.warning(f"源文件 {source_path} 不存在，跳过备份")
                skipped_count += 1
                continue

            # 复制文件
            logger.info(f"备份 {repo_file} 到 {backup_name}...")
            copy_cmd = f"cp {source_path} {backup_path}"
            success, output = self.ssh_tool.run_cmd(copy_cmd)
            if not success:
                logger.error(f"备份 {repo_file} 失败: {output}")
                failed_count += 1
                continue

            # 验证备份文件是否存在
            verify_cmd = f"test -f {backup_path} && echo 'exists' || echo 'not_exists'"
            success, output = self.ssh_tool.run_cmd(verify_cmd)
            if success and output.strip() == "exists":
                logger.info(f"成功备份 {repo_file} 到 {backup_name}")
                success_count += 1
            else:
                logger.error(f"备份文件 {backup_path} 验证失败")
                failed_count += 1

        # 总结备份结果
        if success_count > 0 and failed_count == 0:
            logger.info(
                f"备份完成：成功 {success_count} 个文件"
                + (f"，跳过 {skipped_count} 个不存在的文件" if skipped_count > 0 else "")
            )
            return True
        elif success_count > 0:
            logger.warning(
                f"部分备份完成：成功 {success_count} 个，失败 {failed_count} 个"
                + (f"，跳过 {skipped_count} 个不存在的文件" if skipped_count > 0 else "")
            )
            return True
        elif skipped_count == len(repo_files):
            logger.warning("所有源文件都不存在，无需备份")
            return True
        else:
            logger.error(
                f"备份失败：失败 {failed_count} 个文件"
                + (f"，跳过 {skipped_count} 个不存在的文件" if skipped_count > 0 else "")
            )
            return False

    def replace_yum_repos(self, local_dir: str | None = None) -> bool:
        """替换 yum.repos.d 目录下的源文件

        Args:
            local_dir: 本地目录路径，包含需要上传的源文件（centos.repo 和 centos-addons.repo）
                      默认为 None，使用包内默认的阿里云源配置（sk_lib/static/repo/centos9-aliyun）

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        # 如果未指定本地目录，使用默认的 centos9-aliyun 目录
        if local_dir is None:
            current_file_dir = os.path.dirname(os.path.abspath(__file__))
            local_dir = os.path.join(current_file_dir, "..", "static", "repo", "centos9-aliyun")
            local_dir = os.path.normpath(local_dir)
            logger.info(f"使用默认阿里云源配置: {local_dir}")

        if not self.clean_yum_process():
            return False

        logger.info("开始替换 yum.repos.d 目录下的源文件...")

        repo_dir = "/etc/yum.repos.d"
        repo_files = ["centos.repo", "centos-addons.repo"]

        success_count = 0
        failed_count = 0

        for repo_file in repo_files:
            local_path = os.path.join(local_dir, repo_file)
            remote_path = f"{repo_dir}/{repo_file}"

            # 检查本地文件是否存在
            logger.info(f"检查本地文件是否存在: {local_path}")
            if not os.path.isfile(local_path):
                logger.error(f"本地文件不存在: {local_path}")
                failed_count += 1
                continue

            # 上传文件到远程
            logger.info(f"上传 {repo_file} 到远程服务器...")
            success = self.ssh_tool.upload_file(local_path, remote_path, create_dirs=True)
            if not success:
                logger.error(f"上传 {repo_file} 失败")
                failed_count += 1
                continue

            # 验证远程文件是否存在
            logger.info(f"验证远程文件是否存在: {remote_path}")
            verify_cmd = f"test -f {remote_path} && echo 'exists' || echo 'not_exists'"
            success, output = self.ssh_tool.run_cmd(verify_cmd)
            if success and output.strip() == "exists":
                logger.info(f"成功替换 {repo_file}")
                success_count += 1
            else:
                logger.error(f"远程文件 {remote_path} 验证失败")
                failed_count += 1

        # 总结替换结果
        if success_count == 0:
            logger.error(f"所有源文件替换失败（失败 {failed_count} 个文件）")
            return False

        # 如果有文件成功替换，执行清理和重建缓存
        logger.info(f"源文件替换完成（成功 {success_count} 个，失败 {failed_count} 个）")

        # 清理 yum 缓存
        logger.info("清理 yum 缓存...")
        clean_cmd = "yum clean all"
        clean_cmd_stream = self._wrap_cmd_with_pty(clean_cmd)
        success, output = self.ssh_tool.run_cmd(clean_cmd_stream, realtime_output=True)
        if not success:
            logger.warning(f"清理 yum 缓存失败: {output}")
        else:
            logger.info("yum 缓存清理完成")

        # 重建 yum 缓存
        logger.info("重建 yum 缓存...")
        makecache_cmd = "yum makecache"
        makecache_cmd_stream = self._wrap_cmd_with_pty(makecache_cmd)
        success, output = self.ssh_tool.run_cmd(makecache_cmd_stream, realtime_output=True)
        if not success:
            logger.error(f"重建 yum 缓存失败: {output}")
            return False
        logger.info("yum 缓存重建完成")

        # 验证仓库是否生效
        logger.info("验证仓库是否生效...")
        repolist_cmd = "yum repolist"
        repolist_cmd_stream = self._wrap_cmd_with_pty(repolist_cmd)
        success, output = self.ssh_tool.run_cmd(repolist_cmd_stream, realtime_output=True)
        if success:
            # 检查输出中是否包含仓库信息
            if "repo id" in output.lower() or "repolist" in output.lower():
                logger.info("仓库验证成功，已生效")
                logger.debug(f"仓库列表:\n{output}")
            else:
                logger.warning("仓库验证结果异常，但命令执行成功")
        else:
            logger.error(f"验证仓库失败: {output}")
            return False

        if success_count == len(repo_files):
            logger.info("所有源文件替换并验证完成")
        else:
            logger.warning("部分源文件替换完成，但已执行缓存更新和验证")

        return True

    def restore_yum_repo(self) -> bool:
        """恢复 yum.repos.d 目录下的源文件到默认配置

        使用包内默认的源文件配置（sk_lib/static/repo/centos9-default）替换远程服务器的源文件

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        # 获取包根目录路径
        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        # 从 sk_lib/os_env/linux.py 到 sk_lib/static/repo/centos9-default
        repo_dir = os.path.join(current_file_dir, "..", "static", "repo", "centos9-default")
        repo_dir = os.path.normpath(repo_dir)

        logger.info(f"使用默认源文件配置恢复: {repo_dir}")
        return self.replace_yum_repos(repo_dir)

    def yum_update(self, package_name: str | None = None, clean_cache: bool = True) -> bool:
        """更新系统包

        Args:
            package_name: 指定要更新的包名，如果为 None 则更新所有包
            clean_cache: 是否在更新前清理缓存，默认 True

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info("开始更新系统包...")

        if not linux_env.clean_yum_process():
            return False

        # 根据不同的操作系统平台选择更新命令
        # 清理缓存（可选）
        if clean_cache:
            logger.info("清理 yum 缓存...")
            clean_cmd = "yum clean all"
            success, output = self.ssh_tool.run_cmd(clean_cmd, realtime_output=True)
            if success:
                logger.info("yum 缓存清理成功")
            else:
                logger.warning(f"yum 缓存清理失败: {output}")

        # 构建更新命令
        if package_name:
            update_cmd = f"yum update -y {package_name}"
            logger.info(f"更新指定包: {package_name}")
        else:
            update_cmd = "yum update -y"
            logger.info("更新所有包（这可能需要较长时间）...")

        # 执行更新命令（使用 stdbuf 强制行缓冲，实现实时输出）
        update_cmd_stream = self._wrap_cmd_with_pty(update_cmd)
        success, output = self.ssh_tool.run_cmd(update_cmd_stream, realtime_output=True, timeout=1800)

        if success:
            if package_name:
                logger.info(f"包 {package_name} 更新成功")
            else:
                logger.info("系统包更新成功")
            return True
        else:
            if package_name:
                logger.error(f"包 {package_name} 更新失败: {output}")
            else:
                logger.error(f"系统包更新失败: {output}")
            return False

    def _yum_install(self, soft_name: str) -> bool:
        """yum安装"""
        # 检查是否已经安装（使用 rpm -q）
        success, output = self.ssh_tool.run_cmd(f"rpm -q {soft_name} 2>&1")
        if success and output.strip():
            return True

        install_cmd = f"yum install -y {soft_name}"

        # 执行安装命令（使用 stdbuf 强制行缓冲，改善长时间下载时的输出刷新）
        install_cmd_stream = self._wrap_cmd_with_pty(install_cmd)
        success, output = self.ssh_tool.run_cmd(install_cmd_stream, realtime_output=True)
        if not success:
            return False

        # 验证安装是否成功（使用 rpm -q）
        success, output = self.ssh_tool.run_cmd(f"rpm -q {soft_name} 2>&1", realtime_output=True)
        if success and output.strip():
            logger.info(f"Soft {soft_name} install success")
            return True
        else:
            logger.error(f"Soft {soft_name} install error")
            return False

    def _yum_uninstall(self, soft_name: str) -> bool:
        """yum卸载"""
        success, output = self.ssh_tool.run_cmd(f"yum remove -y {soft_name}")
        flag = success and output.strip() != ""
        if flag:
            logger.info(f"Soft {soft_name} uninstall success")
        else:
            logger.error(f"Soft {soft_name} uninstall error")

        return flag

    def download_python(self, version: str, download_dir: str, replace: bool = False) -> bool:
        """下载指定版本的 Python 源码包

        Args:
            version: Python 版本号，例如 "3.11.0"
            download_dir: 下载目录路径
            replace: 是否覆盖

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info(f"开始下载 Python {version}...")
        source_url = "https://mirrors.huaweicloud.com/python/"

        """
        清华：https://mirrors.tuna.tsinghua.edu.cn/python/
        华为：https://mirrors.huaweicloud.com/python/
        """

        # 构建下载 URL（使用国内镜像源 - 华为云镜像）
        filename = f"Python-{version}.tar.xz"
        url = f"{source_url}/{version}/{filename}"

        # 确保下载目录存在
        logger.info(f"检查下载目录是否存在: {download_dir}")
        mkdir_cmd = f"mkdir -p {download_dir}"
        success, output = self.ssh_tool.run_cmd(mkdir_cmd)
        if not success:
            logger.error(f"创建下载目录失败: {output}")
            return False

        # 构建下载路径
        download_path = os.path.join(download_dir, filename).replace("\\", "/")

        # 检查文件是否已存在
        logger.info(f"检查文件是否已存在: {download_path}")
        check_cmd = f"test -f {download_path} && echo 'exists' || echo 'not_exists'"
        success, output = self.ssh_tool.run_cmd(check_cmd)
        if success and output.strip() == "exists":
            if replace:
                if not self.ssh_tool.remove_file(download_path):
                    return False
            else:
                logger.info(f"文件已存在，跳过下载: {download_path}")
                return True

        # 使用 requests 在本地下载，然后通过 SFTP 上传到远程服务器
        logger.info(f"开始下载: {url}")
        logger.info(f"保存到: {download_path}")

        # 在本地临时目录下载文件
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"-{filename}") as tmp_file:
            local_temp_path = tmp_file.name

        try:
            logger.info("正在从镜像源下载文件到本地...")
            # 使用 requests 下载，支持流式下载和进度显示
            response = requests.get(url, stream=True, timeout=300)
            response.raise_for_status()

            # 获取文件总大小
            total_size = int(response.headers.get("content-length", 0))
            downloaded_size = 0

            # 写入本地临时文件
            with open(local_temp_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        # 每下载 1MB 显示一次进度
                        if downloaded_size % (1024 * 1024) == 0 or downloaded_size == total_size:
                            if total_size > 0:
                                percent = (downloaded_size / total_size) * 100
                                logger.debug(
                                    f"下载进度: {percent:.1f}% ({downloaded_size / 1024 / 1024:.1f}MB / {total_size / 1024 / 1024:.1f}MB)"
                                )
                            else:
                                logger.debug(f"已下载: {downloaded_size / 1024 / 1024:.1f}MB")

            logger.info(f"本地下载完成，文件大小: {downloaded_size / 1024 / 1024:.1f}MB")

            # 通过 SFTP 上传到远程服务器
            logger.info(f"正在上传文件到远程服务器: {download_path}")
            success = self.ssh_tool.upload_file(local_temp_path, download_path, create_dirs=True)

            if not success:
                logger.error(f"上传文件到远程服务器失败: {download_path}")
                return False

            # 验证远程文件是否存在
            logger.info(f"验证远程文件是否存在: {download_path}")
            verify_cmd = f"test -f {download_path} && echo 'exists' || echo 'not_exists'"
            success, output = self.ssh_tool.run_cmd(verify_cmd)
            if success and output.strip() == "exists":
                # 获取文件大小
                size_cmd = f"ls -lh {download_path} | awk '{{print $5}}'"
                success, size_output = self.ssh_tool.run_cmd(size_cmd)
                file_size = size_output.strip() if success else "未知"
                logger.info(f"Python {version} 下载并上传成功: {download_path} (大小: {file_size})")
                return True
            else:
                logger.error(f"远程文件验证失败: {download_path}")
                return False

        except requests.exceptions.RequestException as e:
            logger.error(f"下载 Python {version} 失败: {e}")
            return False

        except Exception as e:
            logger.error(f"下载或上传过程中出错: {e}")
            return False

        finally:
            # 清理本地临时文件
            if os.path.exists(local_temp_path):
                try:
                    os.remove(local_temp_path)
                    logger.debug(f"已清理本地临时文件: {local_temp_path}")
                    return True
                except Exception as e:
                    logger.warning(f"清理本地临时文件失败: {e}")
                    return False

    def _install_pyenv(self, version: str | None = None) -> bool:
        """安装 pyenv（Python 版本管理工具）

        Args:
            version: pyenv 版本号，例如 "v2.3.36"。如果为 None，则安装最新版本

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        if version:
            logger.info(f"开始安装 pyenv (version: {version})...")
        else:
            logger.info("开始安装 pyenv (最新版本)...")

        # 检查是否已经安装 pyenv
        success, output = self.ssh_tool.run_cmd("which pyenv 2>&1")
        if success and output.strip():
            logger.info("pyenv 已经安装，跳过安装步骤")
            return True

        # 步骤 A：检查并安装 git（pyenv 安装需要）
        logger.info("检查 git 是否已安装...")
        success, output = self.ssh_tool.run_cmd("which git 2>&1")
        if not success or not output.strip():
            logger.info("git 未安装，正在安装 git...")
            if not self._yum_install("git"):
                logger.error("git 安装失败，无法继续安装 pyenv")
                return False

        # 检查磁盘空间（确保至少有 100MB 可用空间）
        logger.info("检查磁盘空间...")
        success, output = self.ssh_tool.run_cmd("df -m ~ | tail -1 | awk '{print $4}'")
        if success and output.strip().isdigit():
            available_mb = int(output.strip())
            if available_mb < 100:
                logger.error(f"磁盘空间不足！可用空间: {available_mb}MB，建议至少 100MB")
                return False
            logger.info(f"磁盘可用空间: {available_mb}MB")

        # 强制清理 ~/.pyenv 目录（包括可能存在的损坏文件）
        logger.info("清理旧的 ~/.pyenv 目录（如果存在）...")
        remove_cmd = "rm -rf ~/.pyenv"
        self.ssh_tool.run_cmd(remove_cmd)

        # 再次确认目录已完全删除
        success, output = self.ssh_tool.run_cmd("test -d ~/.pyenv && echo 'exists' || echo 'not_exists'")
        if "exists" == output.strip():
            logger.error("无法删除旧的 ~/.pyenv 目录，可能存在权限问题")
            return False

        logger.info("目录清理完成")

        # 步骤 A：从 gitee 克隆 pyenv 仓库
        logger.info("正在从 gitee 克隆 pyenv 仓库...")
        # 如果指定了版本，需要完整克隆后再切换；否则使用浅克隆获取最新版本
        if version:
            # 完整克隆（不使用 --depth 1）以便切换到指定版本
            clone_cmd = "git clone --progress https://gitee.com/mirrors/pyenv.git ~/.pyenv 2>&1"
        else:
            # 使用浅克隆（--depth 1）减少数据传输，提高成功率
            clone_cmd = "git clone --progress --depth 1 https://gitee.com/mirrors/pyenv.git ~/.pyenv 2>&1"

        # 添加 --progress 参数强制显示进度（即使在非交互式终端）
        success, output = self.ssh_tool.run_cmd(clone_cmd, realtime_output=True)
        if not success:
            logger.error(f"克隆 pyenv 仓库失败: {output}")
            # 清理可能创建的部分目录
            self.ssh_tool.run_cmd("rm -rf ~/.pyenv")
            return False

        logger.info("pyenv 仓库克隆成功")

        # 如果指定了版本，切换到该版本
        if version:
            logger.info(f"切换到版本 {version}...")
            checkout_cmd = f"cd ~/.pyenv && git checkout {version} 2>&1"
            success, output = self.ssh_tool.run_cmd(checkout_cmd)
            if not success:
                logger.error(f"切换到版本 {version} 失败: {output}")
                self.ssh_tool.run_cmd("rm -rf ~/.pyenv")
                return False
            logger.info(f"成功切换到版本 {version}")

        # 步骤 B：设置 shell 环境变量
        logger.info("配置 shell 环境变量...")

        # 检查 ~/.bashrc 是否已经包含 pyenv 配置
        success, output = self.ssh_tool.run_cmd("grep -q 'PYENV_ROOT' ~/.bashrc && echo 'exists' || echo 'not_exists'")
        if "exists" == output.strip():
            logger.info("~/.bashrc 中已存在 pyenv 配置，先删除旧配置...")
            # 删除所有包含 pyenv 或 PYENV_ROOT 的行
            remove_cmds = [
                "sed -i '/PYENV_ROOT/d' ~/.bashrc",
                "sed -i '/pyenv init/d' ~/.bashrc",
            ]
            for cmd in remove_cmds:
                self.ssh_tool.run_cmd(cmd)
            logger.info("已删除旧的 pyenv 配置")

        # 添加 PYENV_ROOT 环境变量
        cmd1 = "echo 'export PYENV_ROOT=\"$HOME/.pyenv\"' >> ~/.bashrc"
        success, output = self.ssh_tool.run_cmd(cmd1)
        if not success:
            logger.error(f"添加 PYENV_ROOT 配置失败: {output}")
            return False

        # 添加 PATH 配置
        cmd2 = "echo '[[ -d $PYENV_ROOT/bin ]] && export PATH=\"$PYENV_ROOT/bin:$PATH\"' >> ~/.bashrc"
        success, output = self.ssh_tool.run_cmd(cmd2)
        if not success:
            logger.error(f"添加 PATH 配置失败: {output}")
            return False

        # 添加 pyenv init 配置
        cmd3 = "echo 'eval \"$(pyenv init - bash)\"' >> ~/.bashrc"
        success, output = self.ssh_tool.run_cmd(cmd3)
        if not success:
            logger.error(f"添加 pyenv init 配置失败: {output}")
            return False

        logger.info("shell 环境变量配置成功")

        # 步骤 C：通过 source 更新环境
        logger.info("更新当前 shell 环境...")
        source_cmd = "source ~/.bashrc 2>&1"
        success, output = self.ssh_tool.run_cmd(source_cmd)
        # source 命令可能返回一些警告，但不影响使用，所以只记录日志
        if output.strip():
            logger.debug(f"source ~/.bashrc 输出: {output}")

        # 验证安装是否成功
        logger.info("验证 pyenv 安装...")
        # 由于 source 只在当前会话生效，需要手动设置环境变量来验证
        verify_cmd = 'export PYENV_ROOT="$HOME/.pyenv" && export PATH="$PYENV_ROOT/bin:$PATH" && pyenv --version'
        success, output = self.ssh_tool.run_cmd(verify_cmd)

        if success and output.strip():
            logger.info(f"✓ pyenv 安装成功！版本: {output.strip()}")
            logger.info("=" * 70)
            logger.info("📌 如何在当前终端使用 pyenv：")
            logger.info("")
            logger.info("   方法1（推荐）：退出当前终端，重新登录服务器")
            logger.info("")
            logger.info("   方法2：在当前终端执行以下命令：")
            logger.info("   source ~/.bashrc")
            logger.info("")
            logger.info("   验证 pyenv 是否可用：")
            logger.info("   pyenv --version")
            logger.info("")
            logger.info("💡 说明：pyenv 环境变量已添加到 ~/.bashrc")
            logger.info("   新的终端会话将自动加载 pyenv 配置")
            logger.info("=" * 70)
            return True
        else:
            logger.error(f"pyenv 安装验证失败: {output}")
            logger.error("请检查安装过程是否有错误")
            return False

    def _install_nvm(self, version: str | None = None) -> bool:
        """安装 nvm（Node Version Manager）

        Args:
            version: nvm 版本号，例如 "v0.40.3"。如果为 None，则安装最新版本

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        if version:
            logger.info(f"开始安装 nvm (version: {version})...")
        else:
            logger.info("开始安装 nvm (最新版本)...")

        # 检查是否已经安装 nvm
        check_cmd = (
            'export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh" && nvm --version 2>&1'
        )
        success, output = self.ssh_tool.run_cmd(check_cmd)
        if success and output.strip() and "command not found" not in output.lower():
            logger.info(f"nvm 已经安装（版本: {output.strip()}），跳过安装步骤")
            return True

        # 检查 git 是否已安装
        logger.info("检查 git 是否已安装...")
        success, output = self.ssh_tool.run_cmd("which git 2>&1")
        if not success or not output.strip():
            logger.info("git 未安装，正在安装 git...")
            if not self._yum_install("git"):
                logger.error("git 安装失败，无法继续安装 nvm")
                return False

        # 检查磁盘空间（确保至少有 50MB 可用空间）
        logger.info("检查磁盘空间...")
        success, output = self.ssh_tool.run_cmd("df -m ~ | tail -1 | awk '{print $4}'")
        if success and output.strip().isdigit():
            available_mb = int(output.strip())
            if available_mb < 50:
                logger.error(f"磁盘空间不足！可用空间: {available_mb}MB，建议至少 50MB")
                return False
            logger.info(f"磁盘可用空间: {available_mb}MB")

        # 强制清理 ~/.nvm 目录（包括可能存在的损坏文件）
        logger.info("清理旧的 ~/.nvm 目录（如果存在）...")
        remove_cmd = "rm -rf ~/.nvm"
        self.ssh_tool.run_cmd(remove_cmd)

        # 再次确认目录已完全删除
        success, output = self.ssh_tool.run_cmd("test -d ~/.nvm && echo 'exists' || echo 'not_exists'")
        if "exists" == output.strip():
            logger.error("无法删除旧的 ~/.nvm 目录，可能存在权限问题")
            return False

        logger.info("目录清理完成")

        # 步骤 1：从 gitee 克隆 nvm 仓库
        logger.info("正在从 gitee 克隆 nvm 仓库...")
        # 如果指定了版本，需要完整克隆后再切换；否则使用浅克隆获取最新版本
        if version:
            # 完整克隆（不使用 --depth 1）以便切换到指定版本
            clone_cmd = "git clone --progress https://gitee.com/mirrors/nvm-sh.git ~/.nvm 2>&1"
        else:
            # 使用浅克隆（--depth 1）减少数据传输，提高成功率
            clone_cmd = "git clone --progress --depth 1 https://gitee.com/mirrors/nvm-sh.git ~/.nvm 2>&1"

        success, output = self.ssh_tool.run_cmd(clone_cmd, realtime_output=True)
        if not success:
            logger.error(f"克隆 nvm 仓库失败: {output}")
            self.ssh_tool.run_cmd("rm -rf ~/.nvm")
            return False

        logger.info("nvm 仓库克隆成功")

        # 如果指定了版本，切换到该版本
        if version:
            logger.info(f"切换到版本 {version}...")
            checkout_cmd = f"cd ~/.nvm && git checkout {version} 2>&1"
            success, output = self.ssh_tool.run_cmd(checkout_cmd)
            if not success:
                logger.error(f"切换到版本 {version} 失败: {output}")
                self.ssh_tool.run_cmd("rm -rf ~/.nvm")
                return False
            logger.info(f"成功切换到版本 {version}")

        # 步骤 3：设置 shell 环境变量
        logger.info("配置 shell 环境变量...")

        # 检查 ~/.bashrc 是否已经包含 nvm 配置
        success, output = self.ssh_tool.run_cmd("grep -q 'NVM_DIR' ~/.bashrc && echo 'exists' || echo 'not_exists'")
        if "exists" == output.strip():
            logger.info("~/.bashrc 中已存在 nvm 配置，先删除旧配置...")
            # 删除所有包含 nvm 或 NVM_DIR 的行
            remove_cmds = [
                "sed -i '/NVM_DIR/d' ~/.bashrc",
                "sed -i '/nvm.sh/d' ~/.bashrc",
                "sed -i '/bash_completion/d' ~/.bashrc",
            ]
            for cmd in remove_cmds:
                self.ssh_tool.run_cmd(cmd)
            logger.info("已删除旧的 nvm 配置")

        # 添加 NVM_DIR 环境变量
        cmd1 = "echo 'export NVM_DIR=\"$HOME/.nvm\"' >> ~/.bashrc"
        success, output = self.ssh_tool.run_cmd(cmd1)
        if not success:
            logger.error(f"添加 NVM_DIR 配置失败: {output}")
            return False

        # 添加 nvm.sh 加载脚本
        cmd2 = 'echo \'[ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh"  # This loads nvm\' >> ~/.bashrc'
        success, output = self.ssh_tool.run_cmd(cmd2)
        if not success:
            logger.error(f"添加 nvm.sh 配置失败: {output}")
            return False

        # 添加 bash_completion 加载脚本
        cmd3 = 'echo \'[ -s "$NVM_DIR/bash_completion" ] && \\. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion\' >> ~/.bashrc'
        success, output = self.ssh_tool.run_cmd(cmd3)
        if not success:
            logger.error(f"添加 bash_completion 配置失败: {output}")
            return False

        logger.info("shell 环境变量配置成功")

        # 步骤 4：通过 source 更新环境
        logger.info("更新当前 shell 环境...")
        source_cmd = "source ~/.bashrc 2>&1"
        success, output = self.ssh_tool.run_cmd(source_cmd)
        if output.strip():
            logger.debug(f"source ~/.bashrc 输出: {output}")

        # 验证安装是否成功
        logger.info("验证 nvm 安装...")
        verify_cmd = 'export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh" && nvm --version'
        success, output = self.ssh_tool.run_cmd(verify_cmd)

        if success and output.strip():
            logger.info(f"✓ nvm 安装成功！版本: {output.strip()}")
            logger.info("=" * 70)
            logger.info("📌 如何在当前终端使用 nvm：")
            logger.info("")
            logger.info("   方法1（推荐）：退出当前终端，重新登录服务器")
            logger.info("")
            logger.info("   方法2：在当前终端执行以下命令：")
            logger.info("   source ~/.bashrc")
            logger.info("")
            logger.info("   验证 nvm 是否可用：")
            logger.info("   nvm --version")
            logger.info("")
            logger.info("   使用 nvm 安装 Node.js：")
            logger.info("   nvm install node        # 安装最新版本")
            logger.info("   nvm install --lts       # 安装最新 LTS 版本")
            logger.info("   nvm install 18.20.0     # 安装指定版本")
            logger.info("")
            logger.info("💡 说明：nvm 环境变量已添加到 ~/.bashrc")
            logger.info("   新的终端会话将自动加载 nvm 配置")
            logger.info("=" * 70)
            return True
        else:
            logger.error(f"nvm 安装验证失败: {output}")
            logger.error("请检查安装过程是否有错误")
            return False

    def _uninstall_pyenv(self) -> bool:
        """卸载 pyenv（Python 版本管理工具）

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info("开始卸载 pyenv...")

        # 检查是否已经安装 pyenv
        success, output = self.ssh_tool.run_cmd("which pyenv 2>&1")
        if not success or not output.strip():
            success, output = self.ssh_tool.run_cmd("test -d ~/.pyenv && echo 'exists' || echo 'not_exists'")
            if "not_exists" == output.strip():
                logger.info("pyenv 未安装，无需卸载")
                return True

        # 步骤 1：删除 ~/.pyenv 目录
        logger.info("删除 ~/.pyenv 目录...")
        remove_cmd = "rm -rf ~/.pyenv"
        success, output = self.ssh_tool.run_cmd(remove_cmd)
        if not success:
            logger.error(f"删除 ~/.pyenv 目录失败: {output}")
            return False
        logger.info("已删除 ~/.pyenv 目录")

        # 步骤 2：从 ~/.bashrc 中删除 pyenv 配置
        logger.info("清理 ~/.bashrc 中的 pyenv 配置...")
        remove_cmds = [
            "sed -i '/PYENV_ROOT/d' ~/.bashrc",
            "sed -i '/pyenv init/d' ~/.bashrc",
        ]
        for cmd in remove_cmds:
            self.ssh_tool.run_cmd(cmd)
        logger.info("已清理 ~/.bashrc 中的 pyenv 配置")

        # 验证卸载是否成功
        logger.info("验证 pyenv 卸载...")
        success, output = self.ssh_tool.run_cmd("test -d ~/.pyenv && echo 'exists' || echo 'not_exists'")
        if "not_exists" == output.strip():
            logger.info("✓ pyenv 卸载成功！")
            logger.info("=" * 70)
            logger.info("📌 提示：")
            logger.info("")
            logger.info("   为了使配置生效，请执行以下操作之一：")
            logger.info("")
            logger.info("   方法1（推荐）：退出当前终端，重新登录服务器")
            logger.info("")
            logger.info("   方法2：在当前终端执行以下命令：")
            logger.info("   source ~/.bashrc")
            logger.info("")
            logger.info("=" * 70)
            return True
        else:
            logger.error("pyenv 卸载验证失败，~/.pyenv 目录仍然存在")
            return False

    def _uninstall_nvm(self) -> bool:
        """卸载 nvm（Node Version Manager）

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info("开始卸载 nvm...")

        # 检查是否已经安装 nvm
        success, output = self.ssh_tool.run_cmd("test -d ~/.nvm && echo 'exists' || echo 'not_exists'")
        if "not_exists" == output.strip():
            logger.info("nvm 未安装，无需卸载")
            return True

        # 步骤 1：删除 ~/.nvm 目录
        logger.info("删除 ~/.nvm 目录...")
        remove_cmd = "rm -rf ~/.nvm"
        success, output = self.ssh_tool.run_cmd(remove_cmd)
        if not success:
            logger.error(f"删除 ~/.nvm 目录失败: {output}")
            return False
        logger.info("已删除 ~/.nvm 目录")

        # 步骤 2：从 ~/.bashrc 中删除 nvm 配置
        logger.info("清理 ~/.bashrc 中的 nvm 配置...")
        remove_cmds = [
            "sed -i '/NVM_DIR/d' ~/.bashrc",
            "sed -i '/nvm.sh/d' ~/.bashrc",
            "sed -i '/bash_completion/d' ~/.bashrc",
        ]
        for cmd in remove_cmds:
            self.ssh_tool.run_cmd(cmd)
        logger.info("已清理 ~/.bashrc 中的 nvm 配置")

        # 验证卸载是否成功
        logger.info("验证 nvm 卸载...")
        success, output = self.ssh_tool.run_cmd("test -d ~/.nvm && echo 'exists' || echo 'not_exists'")
        if "not_exists" == output.strip():
            logger.info("✓ nvm 卸载成功！")
            logger.info("=" * 70)
            logger.info("📌 提示：")
            logger.info("")
            logger.info("   为了使配置生效，请执行以下操作之一：")
            logger.info("")
            logger.info("   方法1（推荐）：退出当前终端，重新登录服务器")
            logger.info("")
            logger.info("   方法2：在当前终端执行以下命令：")
            logger.info("   source ~/.bashrc")
            logger.info("")
            logger.info("=" * 70)
            return True
        else:
            logger.error("nvm 卸载验证失败，~/.nvm 目录仍然存在")
            return False

    def set_english_locale(self) -> bool:
        """设置操作系统为英文环境"""

        # 检查并安装英文locale（如果未安装）
        success, output = self.ssh_tool.run_cmd("locale -a | grep -i 'en_US.utf8' || echo ''")
        if not success or not output.strip():
            logger.info("Installing en_US.UTF-8 locale...")
            # 对于CentOS/RHEL，需要安装 glibc-langpack-en 或 locales-all
            install_cmd = "yum install -y glibc-langpack-en 2>/dev/null || yum install -y glibc-locale-source glibc-locale 2>/dev/null || echo 'Locale package install may have failed'"
            success, output = self.ssh_tool.run_cmd(install_cmd, realtime_output=True)
            if not success:
                logger.warning("Failed to install locale package, continuing anyway...")

        # 生成locale（如果需要）
        logger.info("Generating en_US.UTF-8 locale...")
        success, output = self.ssh_tool.run_cmd(
            "localedef -i en_US -f UTF-8 en_US.UTF-8 2>&1 || echo 'Locale may already exist'"
        )

        # 设置系统级别的locale（对于systemd系统）
        logger.info("Setting system locale to en_US.UTF-8...")
        success, output = self.ssh_tool.run_cmd("localectl set-locale LANG=en_US.UTF-8 2>&1")
        if not success:
            # 如果localectl不可用，直接修改 /etc/locale.conf
            logger.info("localectl not available, modifying /etc/locale.conf directly...")
            backup_cmd = "cp /etc/locale.conf /etc/locale.conf.bak 2>/dev/null || true"
            self.ssh_tool.run_cmd(backup_cmd)

            set_locale_cmd = "echo 'LANG=en_US.UTF-8' > /etc/locale.conf"
            success, output = self.ssh_tool.run_cmd(set_locale_cmd)
            if not success:
                logger.error(f"Failed to set locale: {output}")
                return False

        # 设置当前会话的环境变量
        logger.info("Setting locale environment variables for current session...")
        export_cmd = "export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8"
        self.ssh_tool.run_cmd(export_cmd)

        # 验证设置是否成功
        success, output = self.ssh_tool.run_cmd("locale | grep LANG")
        if success and "en_US.UTF-8" in output:
            logger.info("Locale set to en_US.UTF-8 successfully")
            logger.info(f"Current locale: {output.strip()}")
            return True
        else:
            logger.warning("Locale setting may not have taken effect immediately")
            logger.warning("A system reboot may be required for full effect")
            return True  # 返回True，因为配置已写入，只是需要重启生效

    def get_system_info(self) -> dict:
        """获取系统信息字典"""
        system_info = {}

        # 获取主机名
        success, output = self.ssh_tool.run_cmd("hostname")
        if success:
            system_info["hostname"] = output.strip()
        else:
            system_info["hostname"] = "unknown"
            logger.warning("Failed to get hostname")

        # 获取用户名
        success, output = self.ssh_tool.run_cmd("whoami")
        if success:
            system_info["username"] = output.strip()
        else:
            system_info["username"] = "unknown"
            logger.warning("Failed to get username")

        # 获取是否为管理员（root）
        success, output = self.ssh_tool.run_cmd("id -u")
        if success:
            try:
                user_id = int(output.strip())
                system_info["is_admin"] = user_id == 0
            except ValueError:
                # 如果无法解析用户ID，通过检查用户名是否为root
                success, username_output = self.ssh_tool.run_cmd("whoami")
                if success:
                    system_info["is_admin"] = username_output.strip() == "root"
                else:
                    system_info["is_admin"] = False
        else:
            system_info["is_admin"] = False
            logger.warning("Failed to get admin status")

        # 获取操作系统信息（优先使用 /etc/os-release）
        success, output = self.ssh_tool.run_cmd("cat /etc/os-release 2>/dev/null || echo ''")
        if success and output.strip():
            os_info = {}
            for line in output.strip().split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    os_info[key.lower()] = value

            system_info["os_type"] = os_info.get("id", "unknown")
            system_info["os_name"] = os_info.get("pretty_name", "unknown")
            system_info["os_version"] = os_info.get("version_id", os_info.get("version", "unknown"))
        else:
            # 如果 /etc/os-release 不存在，使用 uname
            success, output = self.ssh_tool.run_cmd("uname -s")
            if success:
                system_info["os_name"] = output.strip()
            else:
                system_info["os_name"] = "unknown"

            success, output = self.ssh_tool.run_cmd("uname -r")
            if success:
                system_info["os_version"] = output.strip()
            else:
                system_info["os_version"] = "unknown"

        # 获取内核版本
        success, output = self.ssh_tool.run_cmd("uname -r")
        if success:
            system_info["kernel_version"] = output.strip()
        else:
            system_info["kernel_version"] = "unknown"
            logger.warning("Failed to get kernel version")

        # 获取系统架构
        success, output = self.ssh_tool.run_cmd("uname -m")
        if success:
            system_info["architecture"] = output.strip()
        else:
            system_info["architecture"] = "unknown"
            logger.warning("Failed to get architecture")

        # 获取 CPU 信息
        success, output = self.ssh_tool.run_cmd(
            "lscpu 2>/dev/null | grep 'Model name' | cut -d':' -f2 | xargs || echo ''"
        )
        if success and output.strip():
            system_info["cpu_model"] = output.strip()
        else:
            success, output = self.ssh_tool.run_cmd(
                "cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2 | xargs || echo ''"
            )
            if success and output.strip():
                system_info["cpu_model"] = output.strip()
            else:
                system_info["cpu_model"] = "unknown"

        # 获取 CPU 核心数
        success, output = self.ssh_tool.run_cmd("nproc")
        if success:
            try:
                system_info["cpu_cores"] = int(output.strip())
            except ValueError:
                system_info["cpu_cores"] = "unknown"
        else:
            system_info["cpu_cores"] = "unknown"

        # 获取物理 CPU 插槽数 (Sockets)
        success, output = self.ssh_tool.run_cmd("lscpu 2>/dev/null | grep '^Socket(s):' | awk '{print $2}'")
        if success and output.strip():
            try:
                system_info["cpu_sockets"] = int(output.strip())
            except ValueError:
                system_info["cpu_sockets"] = "unknown"
        else:
            system_info["cpu_sockets"] = "unknown"

        # 获取每插槽核心数 (Cores per socket)
        success, output = self.ssh_tool.run_cmd("lscpu 2>/dev/null | grep '^Core(s) per socket:' | awk '{print $4}'")
        if success and output.strip():
            try:
                system_info["cores_per_socket"] = int(output.strip())
            except ValueError:
                system_info["cores_per_socket"] = "unknown"
        else:
            system_info["cores_per_socket"] = "unknown"

        # 获取每核心线程数 (Threads per core)
        success, output = self.ssh_tool.run_cmd("lscpu 2>/dev/null | grep '^Thread(s) per core:' | awk '{print $4}'")
        if success and output.strip():
            try:
                system_info["threads_per_core"] = int(output.strip())
            except ValueError:
                system_info["threads_per_core"] = "unknown"
        else:
            system_info["threads_per_core"] = "unknown"

        # 获取总逻辑 CPU 数
        success, output = self.ssh_tool.run_cmd("lscpu 2>/dev/null | grep '^CPU(s):' | awk '{print $2}'")
        if success and output.strip():
            try:
                system_info["total_logical_cpus"] = int(output.strip())
            except ValueError:
                system_info["total_logical_cpus"] = "unknown"
        else:
            system_info["total_logical_cpus"] = "unknown"

        # 从 /proc/meminfo 获取内存信息（单位：KB）
        # 获取 MemTotal
        success, output = self.ssh_tool.run_cmd("grep '^MemTotal:' /proc/meminfo | awk '{print $2}'")
        if success and output.strip():
            try:
                system_info["total_memory"] = int(output.strip())
            except ValueError:
                system_info["total_memory"] = "unknown"
        else:
            system_info["total_memory"] = "unknown"

        # 获取 MemFree
        success, output = self.ssh_tool.run_cmd("grep '^MemFree:' /proc/meminfo | awk '{print $2}'")
        if success and output.strip():
            try:
                system_info["free_memory"] = int(output.strip())
            except ValueError:
                system_info["free_memory"] = "unknown"
        else:
            system_info["free_memory"] = "unknown"

        # 获取 MemAvailable
        success, output = self.ssh_tool.run_cmd("grep '^MemAvailable:' /proc/meminfo | awk '{print $2}'")
        if success and output.strip():
            try:
                system_info["available_memory"] = int(output.strip())
            except ValueError:
                system_info["available_memory"] = "unknown"
        else:
            system_info["available_memory"] = "unknown"

        logger.info(f"System info collected: \n{json.dumps(system_info, indent=4)}")
        return system_info

    def set_timezone(self, timezone: str = "Asia/Shanghai") -> bool:
        """设置系统时区

        Args:
            timezone: 时区名称，默认 'Asia/Shanghai'，例如 'UTC', 'America/New_York' 等

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info(f"设置系统时区为: {timezone}")

        # 优先使用 timedatectl（systemd 系统）
        success, output = self.ssh_tool.run_cmd(f"timedatectl set-timezone {timezone} 2>&1")
        if success:
            # 验证时区是否设置成功
            verify_success, verify_output = self.ssh_tool.run_cmd("timedatectl | grep 'Time zone'")
            if verify_success and timezone in verify_output:
                logger.info(f"成功设置时区为: {timezone}")
                return True
            else:
                logger.warning(f"时区设置命令执行成功，但验证失败: {verify_output}")
                return True  # 仍然返回 True，因为命令执行成功

        # 如果 timedatectl 不可用，使用传统方法
        logger.debug("timedatectl 不可用，使用传统方法设置时区...")

        # 检查时区文件是否存在
        timezone_file = f"/usr/share/zoneinfo/{timezone}"
        check_success, check_output = self.ssh_tool.run_cmd(
            f"test -f {timezone_file} && echo 'exists' || echo 'not exists'"
        )
        if not check_success or "not exists" in check_output:
            logger.error(f"时区文件不存在: {timezone_file}")
            return False

        # 创建符号链接
        backup_cmd = "cp /etc/localtime /etc/localtime.bak 2>/dev/null || true"
        self.ssh_tool.run_cmd(backup_cmd)

        link_cmd = f"ln -sf {timezone_file} /etc/localtime"
        success, output = self.ssh_tool.run_cmd(link_cmd)
        if success:
            logger.info(f"成功设置时区为: {timezone}")
            return True
        else:
            logger.error(f"设置时区失败: {output}")
            return False

    def sync_time_with_ntp(self, ntp_server: str = "pool.ntp.org") -> bool:
        """与NTP服务器同步时间

        Args:
            ntp_server: NTP服务器地址，默认 'pool.ntp.org'

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info(f"与NTP服务器同步时间: {ntp_server}")

        # 优先使用 chronyd（CentOS 7+ 默认）
        success, output = self.ssh_tool.run_cmd("systemctl is-active chronyd 2>&1")
        if success and output.strip() == "active":
            # 使用 chronyd 同步时间
            logger.debug("使用 chronyd 同步时间...")
            # 先停止 chronyd
            self.ssh_tool.run_cmd("systemctl stop chronyd 2>&1")
            # 使用 chronyd 手动同步
            sync_cmd = f"chronyd -q 'server {ntp_server} iburst' 2>&1"
            success, output = self.ssh_tool.run_cmd(sync_cmd)
            # 重新启动 chronyd
            self.ssh_tool.run_cmd("systemctl start chronyd 2>&1")
            if success:
                logger.info(f"成功与NTP服务器同步时间: {ntp_server}")
                return True
            else:
                logger.warning(f"chronyd 同步失败，尝试其他方法: {output}")

        # 尝试使用 ntpdate
        logger.debug("尝试使用 ntpdate 同步时间...")
        # 检查 ntpdate 是否可用
        check_success, _ = self.ssh_tool.run_cmd("which ntpdate 2>&1")
        if check_success:
            sync_cmd = f"ntpdate -u {ntp_server} 2>&1"
            success, output = self.ssh_tool.run_cmd(sync_cmd)
            if success:
                logger.info(f"成功与NTP服务器同步时间: {ntp_server}")
                return True
            else:
                logger.warning(f"ntpdate 同步失败: {output}")

        # 尝试使用 systemd-timesyncd（systemd 系统）
        logger.debug("尝试使用 systemd-timesyncd 同步时间...")
        success, output = self.ssh_tool.run_cmd("systemctl is-active systemd-timesyncd 2>&1")
        if success and output.strip() == "active":
            # 使用 timedatectl 设置NTP服务器并同步
            set_ntp_cmd = f"timedatectl set-ntp true 2>&1"
            self.ssh_tool.run_cmd(set_ntp_cmd)
            # 等待同步完成
            time.sleep(2)
            # 手动触发同步（如果支持）
            sync_cmd = "systemctl restart systemd-timesyncd 2>&1"
            success, output = self.ssh_tool.run_cmd(sync_cmd)
            if success:
                logger.info(f"成功与NTP服务器同步时间: {ntp_server}")
                return True

        # 如果所有方法都失败，尝试使用 rdate（较老的方法）
        logger.debug("尝试使用 rdate 同步时间...")
        check_success, _ = self.ssh_tool.run_cmd("which rdate 2>&1")
        if check_success:
            sync_cmd = f"rdate -s {ntp_server} 2>&1"
            success, output = self.ssh_tool.run_cmd(sync_cmd)
            if success:
                logger.info(f"成功与NTP服务器同步时间: {ntp_server}")
                return True

        logger.error(f"无法与NTP服务器同步时间: {ntp_server}，所有方法都失败")
        return False

    def get_current_time(self) -> str:
        """获取当前系统时间

        Returns:
            str: 当前时间的字符串表示，格式为 ISO 8601 格式 (YYYY-MM-DD HH:MM:SS)
        """
        # 使用 date 命令获取当前时间
        cmd = "date '+%Y-%m-%d %H:%M:%S'"
        logger.debug(f"执行命令: {cmd}")

        success, output = self.ssh_tool.run_cmd(cmd)
        if success and output.strip():
            current_time = output.strip()
            logger.debug(f"当前系统时间: {current_time}")
            return current_time
        else:
            logger.error(f"获取当前时间失败: {output}")
            return ""

    def service_start(self, service_name: str) -> bool:
        """启动服务

        Args:
            service_name: 服务名称，例如 'nginx', 'mysql', 'docker' 等

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info(f"启动服务: {service_name}")

        # 使用 systemctl 启动服务
        cmd = f"systemctl start {service_name}"
        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            logger.info(f"成功启动服务: {service_name}")
            return True
        else:
            logger.error(f"启动服务失败: {service_name}, 错误: {output}")
            return False

    def service_stop(self, service_name: str) -> bool:
        """停止服务

        Args:
            service_name: 服务名称，例如 'nginx', 'mysql', 'docker' 等

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info(f"停止服务: {service_name}")

        # 使用 systemctl 停止服务
        cmd = f"systemctl stop {service_name}"
        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            logger.info(f"成功停止服务: {service_name}")
            return True
        else:
            logger.error(f"停止服务失败: {service_name}, 错误: {output}")
            return False

    def service_restart(self, service_name: str) -> bool:
        """重启服务

        Args:
            service_name: 服务名称，例如 'nginx', 'mysql', 'docker' 等

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info(f"重启服务: {service_name}")

        # 使用 systemctl 重启服务
        cmd = f"systemctl restart {service_name}"
        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            logger.info(f"成功重启服务: {service_name}")
            return True
        else:
            logger.error(f"重启服务失败: {service_name}, 错误: {output}")
            return False

    def service_status(self, service_name: str) -> str:
        """获取服务状态

        Args:
            service_name: 服务名称，例如 'nginx', 'mysql', 'docker' 等

        Returns:
            str: 服务状态，可能的值：
                - 'active': 服务正在运行
                - 'inactive': 服务已停止
                - 'failed': 服务启动失败
                - 'activating': 服务正在启动中
                - 'deactivating': 服务正在停止中
                - 'unknown': 无法确定状态或服务不存在
        """
        logger.debug(f"获取服务状态: {service_name}")

        # 使用 systemctl is-active 获取服务状态
        cmd = f"systemctl is-active {service_name}"
        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            status = output.strip()
            # systemctl is-active 返回 'active' 或 'inactive'
            if status == "active":
                logger.debug(f"服务 {service_name} 状态: active")
                return "active"
            elif status == "inactive":
                logger.debug(f"服务 {service_name} 状态: inactive")
                return "inactive"
            else:
                logger.debug(f"服务 {service_name} 状态: {status}")
                return status
        else:
            # 如果 is-active 失败，尝试使用 status 命令获取更详细的信息
            cmd = f"systemctl status {service_name} --no-pager -l 2>&1 | head -3"
            success, output = self.ssh_tool.run_cmd(cmd)
            if success and output.strip():
                # 解析状态输出
                output_lower = output.lower()
                if "active (running)" in output_lower:
                    return "active"
                elif "inactive (dead)" in output_lower:
                    return "inactive"
                elif "failed" in output_lower:
                    return "failed"
                elif "activating" in output_lower:
                    return "activating"
                elif "deactivating" in output_lower:
                    return "deactivating"

            logger.warning(f"无法获取服务状态: {service_name}, 可能服务不存在")
            return "unknown"

    def service_enable(self, service_name: str) -> bool:
        """启用服务开机自启

        Args:
            service_name: 服务名称，例如 'nginx', 'mysql', 'docker' 等

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info(f"启用服务开机自启: {service_name}")

        # 使用 systemctl enable 启用服务开机自启
        cmd = f"systemctl enable {service_name}"
        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            logger.info(f"成功启用服务开机自启: {service_name}")
            return True
        else:
            logger.error(f"启用服务开机自启失败: {service_name}, 错误: {output}")
            return False

    def service_disable(self, service_name: str) -> bool:
        """禁用服务开机自启

        Args:
            service_name: 服务名称，例如 'nginx', 'mysql', 'docker' 等

        Returns:
            bool: 成功返回 True，失败返回 False
        """
        logger.info(f"禁用服务开机自启: {service_name}")

        # 使用 systemctl disable 禁用服务开机自启
        cmd = f"systemctl disable {service_name}"
        success, output = self.ssh_tool.run_cmd(cmd)

        if success:
            logger.info(f"成功禁用服务开机自启: {service_name}")
            return True
        else:
            logger.error(f"禁用服务开机自启失败: {service_name}, 错误: {output}")
            return False


if __name__ == "__main__":
    linux_env = LinuxEnv(os_platform=OsPlatform.Centos, ip="192.168.137.200", username="root", password="root")
    # linux_env = LinuxEnv(os_platform=OsPlatform.Centos, ip="192.168.203.227", username="root", password="root")
    linux_env.install_soft("nvm")
