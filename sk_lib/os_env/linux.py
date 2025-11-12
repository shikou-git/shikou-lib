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
    linux_env.get_system_info()
