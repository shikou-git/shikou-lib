from loguru import logger

from sk_lib.network import SSHTool


class LinuxEnv:
    def __init__(self, ip: str, username: str, password: str, port: int = 22):
        self.ssh_tool = SSHTool(ip, port, username, password)

    def install_nginx(self) -> tuple[bool, str]:
        """
        在远程主机上安装 nginx。

        支持：
            - Ubuntu (apt)
            - CentOS (dnf/yum)

        步骤：
            1. 检查是否已安装
            2. 识别系统类型
            3. 安装 nginx
            4. 启动并启用服务
            5. 验证 nginx 是否可运行

        Returns:
            tuple[bool, str]: (是否成功, 详细信息)
        """
        # 1. 先检查是否已安装
        # 使用 test -x 检查常见路径，避免依赖 PATH 环境变量
        success, _ = self.ssh_tool.run_cmd(
            "test -x /usr/sbin/nginx || test -x /usr/bin/nginx || command -v nginx >/dev/null 2>&1"
        )
        if success:
            logger.info("nginx 已安装，跳过安装步骤")
            # 确保服务正在运行
            self._ensure_nginx_running()
            return True, "nginx 已安装并运行"

        # 2. 识别操作系统
        os_info = self._detect_os()
        if not os_info:
            return False, "无法识别操作系统类型，不支持自动安装 nginx"

        distro, version = os_info
        logger.debug(f"检测到操作系统: {distro} {version}")

        # 3. 根据发行版安装
        try:
            if distro == "ubuntu":
                success, msg = self._install_nginx_ubuntu()
            elif distro == "centos":
                success, msg = self._install_nginx_centos()
            else:
                return False, f"不支持的操作系统: {distro}，仅支持 Ubuntu 和 CentOS"

            if not success:
                return False, f"安装失败: {msg}"
        except Exception as e:
            logger.exception("安装过程中发生异常")
            return False, f"安装异常: {e}"

        # 4. 确保服务运行
        if not self._ensure_nginx_running():
            return False, "nginx 安装成功，但无法启动服务"

        # 5. 最终验证
        success, output = self.ssh_tool.run_cmd("nginx -v 2>&1")
        if success or ("nginx version" in output):
            logger.info("nginx 安装并验证成功")
            return True, "nginx 安装成功"
        else:
            return False, f"nginx 安装完成但验证失败: {output}"

    def _detect_os(self) -> tuple[str, str] | None:
        """返回 (distro, version)，如 ('ubuntu', '22.04')"""
        # 尝试读取 /etc/os-release（现代 Linux 标准）
        success, output = self.ssh_tool.run_cmd("cat /etc/os-release 2>/dev/null")
        if not success:
            return None

        info = {}
        for line in output.splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                info[key.strip()] = val.strip().strip('"')

        id_ = info.get("ID", "").lower()
        version_id = info.get("VERSION_ID", "").strip()

        # 标准化发行版名称，仅支持 Ubuntu 和 CentOS
        if id_ == "ubuntu":
            return "ubuntu", version_id
        elif id_ == "centos":
            return "centos", version_id
        else:
            return None

    def _install_nginx_ubuntu(self) -> tuple[bool, str]:
        success, _ = self.ssh_tool.run_cmd("apt update -y")
        if not success:
            return False, "apt update 失败"

        success, output = self.ssh_tool.run_cmd("apt install -y nginx")
        if not success:
            return False, f"apt install nginx 失败: {output}"
        return True, "nginx 已通过 apt 安装"

    def _install_nginx_centos(self) -> tuple[bool, str]:
        # CentOS 7 可能只有 yum，新版本用 dnf
        # 使用 test -x 检查常见路径，避免依赖 PATH 环境变量
        pkg_manager = "dnf"
        success, _ = self.ssh_tool.run_cmd("test -x /usr/bin/dnf || command -v dnf >/dev/null 2>&1")
        if not success:
            pkg_manager = "yum"

        cmd = f"{pkg_manager} install -y nginx"
        success, output = self.ssh_tool.run_cmd(cmd)
        if not success:
            return False, f"{pkg_manager} install nginx 失败: {output}"
        return True, f"nginx 已通过 {pkg_manager} 安装"

    def _ensure_nginx_running(self) -> bool:
        """尝试启动并启用 nginx 服务（使用 systemd）"""
        # 检查服务是否已在运行
        success, _ = self.ssh_tool.run_cmd("systemctl is-active nginx")
        if success:
            logger.debug("nginx 服务已在运行")
            return True

        # 尝试启动服务
        start_success, _ = self.ssh_tool.run_cmd("systemctl start nginx")
        if start_success:
            self.ssh_tool.run_cmd("systemctl enable nginx")  # 开机自启
            logger.info("nginx 服务已启动并启用")
            return True

        logger.error("无法启动 nginx 服务")
        return False


if __name__ == "__main__":
    linux_env = LinuxEnv(ip="112.74.95.128", username="ecs-user", password="MIMA100aly+")
    linux_env.install_nginx()
