import json
import time

from loguru import logger

from sk_lib.network import SSHTool
from sk_lib.public.enums import LinuxSoft, OsPlatform


class LinuxEnv:
    def __init__(
        self, ip: str, username: str, password: str, port: int = 22, os_platform: OsPlatform = OsPlatform.Centos
    ):
        self.ssh_tool = SSHTool(ip, port, username, password)
        self.os_platform = os_platform

    def reboot(self) -> bool:
        """重启系统"""
        success, output = self.ssh_tool.run_cmd("reboot")
        if success:
            logger.debug("Reboot system success")
        else:
            logger.error(f"Reboot system error: {output}")
            return False

        return True

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

    def install_soft(self, linux_soft: LinuxSoft | str) -> bool:
        """安装软件"""
        if isinstance(linux_soft, LinuxSoft):
            linux_soft = linux_soft.value

        return self._yum_install(linux_soft)

    def uninstall_soft(self, linux_soft: LinuxSoft | str) -> bool:
        """卸载软件"""
        if isinstance(linux_soft, LinuxSoft):
            linux_soft = linux_soft.value

        return self._yum_uninstall(linux_soft)

    def _yum_install(self, soft_name: str) -> bool:
        """yum安装"""
        # 检查是否已经安装
        success, output = self.ssh_tool.run_cmd(f"which {soft_name}")
        if success and output.strip():
            return True

        # 根据不同的操作系统平台选择安装命令
        if self.os_platform == OsPlatform.Centos:
            install_cmd = f"yum install -y {soft_name}"
        else:
            raise ValueError("OsPlatform not supported")

        # 执行安装命令
        success, output = self.ssh_tool.run_cmd(install_cmd, realtime_output=True)
        if not success:
            return False

        # 验证安装是否成功
        success, output = self.ssh_tool.run_cmd(f"which {soft_name}", realtime_output=True)
        flag = success and output.strip() != ""
        if flag:
            logger.info(f"LinuxSoft {soft_name} install success")
        else:
            logger.error(f"LinuxSoft {soft_name} install error")

        return flag

    def _yum_uninstall(self, soft_name: str) -> bool:
        """yum卸载"""
        success, output = self.ssh_tool.run_cmd(f"yum remove -y {soft_name}")
        flag = success and output.strip() != ""
        if flag:
            logger.info(f"LinuxSoft {soft_name} uninstall success")
        else:
            logger.error(f"LinuxSoft {soft_name} uninstall error")

        return flag

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


if __name__ == "__main__":
    linux_env = LinuxEnv(ip="192.168.137.220", username="root", password="root")
    res = linux_env.get_open_ports_info()
    print(json.dumps(res, indent=4))
