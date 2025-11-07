import os
import time

from loguru import logger

from sk_lib.network.ssh_tool import SSHTool


class FEDeploy:
    """前端部署工具

    支持 Vue/Angular/React 打包后的 dist 或 build 目录部署
    """

    def __init__(self, ssh_tool: SSHTool):
        """初始化前端部署工具

        Args:
            ssh_tool: SSHTool 实例
        """
        if ssh_tool:
            self.ssh_tool = ssh_tool
        else:
            raise ValueError("必须提供 ssh_tool")

    def deploy(
        self,
        local_build_dir: str,
        remote_deploy_path: str,
        backup: bool = True,
        backup_suffix: str | None = None,
    ) -> tuple[bool, str]:
        """部署前端打包文件到服务器

        Args:
            local_build_dir: 本地打包目录路径（dist 或 build）
            remote_deploy_path: 服务器部署路径（如 /var/www/html/myapp）
            backup: 是否备份旧版本
            backup_suffix: 备份目录后缀，默认使用时间戳

        Returns:
            tuple[bool, str]: (是否成功, 消息)
        """
        try:
            # 验证本地目录是否存在
            if not os.path.exists(local_build_dir):
                return False, f"本地打包目录不存在: {local_build_dir}"

            if not os.path.isdir(local_build_dir):
                return False, f"路径不是目录: {local_build_dir}"

            # 检查目录是否为空
            if not os.listdir(local_build_dir):
                return False, f"打包目录为空: {local_build_dir}"

            # 备份旧版本
            if backup:
                backup_result = self._backup_old_version(remote_deploy_path, backup_suffix)
                if not backup_result[0]:
                    logger.warning(f"备份失败，继续部署: {backup_result[1]}")
                    return False, backup_result[1]

            # 如果目标目录存在，先删除
            if self.ssh_tool.path_exists(remote_deploy_path):
                logger.info(f"删除旧版本目录: {remote_deploy_path}")
                if not self.ssh_tool.remove_dir(remote_deploy_path):
                    logger.warning(f"删除旧版本目录失败，继续部署: {remote_deploy_path}")

            # 创建部署目录
            if not self.ssh_tool.mkdir(remote_deploy_path):
                return False, f"创建部署目录失败: {remote_deploy_path}"

            # 上传文件
            logger.info(f"开始上传文件: {local_build_dir} -> {remote_deploy_path}")
            if not self.ssh_tool.upload_dir(local_build_dir, remote_deploy_path):
                return False, f"上传文件失败: {local_build_dir} -> {remote_deploy_path}"

            logger.info(f"部署成功: {local_build_dir} -> {remote_deploy_path}")
            return True, f"部署成功到 {remote_deploy_path}"

        except Exception as e:
            logger.error(f"部署失败: {e}")
            return False, f"部署失败: {str(e)}"

    def _backup_old_version(self, remote_deploy_path: str, backup_suffix: str | None = None) -> tuple[bool, str]:
        """备份旧版本

        Args:
            remote_deploy_path: 部署路径
            backup_suffix: 备份后缀，默认使用时间戳

        Returns:
            tuple[bool, str]: (是否成功, 消息)
        """
        try:
            if not self.ssh_tool.path_exists(remote_deploy_path):
                return True, "旧版本不存在，无需备份"

            if backup_suffix is None:
                backup_suffix = time.strftime("%Y%m%d_%H%M%S")

            backup_path = f"{remote_deploy_path}_backup_{backup_suffix}"

            # 重命名旧版本为备份
            if self.ssh_tool.rename(remote_deploy_path, backup_path):
                logger.info(f"备份成功: {remote_deploy_path} -> {backup_path}")
                return True, f"备份成功到 {backup_path}"
            else:
                return False, f"备份失败: 无法重命名 {remote_deploy_path}"

        except Exception as e:
            logger.error(f"备份失败: {e}")
            return False, f"备份失败: {str(e)}"

    def config_nginx(
        self,
        server_name: str,
        deploy_path: str,
        nginx_config_path: str = "/etc/nginx/conf.d",
        port: int = 80,
        root_path: str | None = None,
        index_file: str = "index.html",
        enable_gzip: bool = True,
        enable_cache: bool = True,
        cache_max_age: int = 7,
        ssl_cert_path: str | None = None,
        ssl_key_path: str | None = None,
        ssl_port: int = 443,
        redirect_http_to_https: bool = False,
        proxy_pass: str | None = None,
        custom_config: str | None = None,
    ) -> tuple[bool, str]:
        """配置 Nginx

        Args:
            server_name: 服务器名称（域名）
            deploy_path: 前端文件部署路径
            nginx_config_path: Nginx 配置目录，默认 /etc/nginx/conf.d
            port: HTTP 端口，默认 80
            root_path: 网站根路径，默认使用 deploy_path
            index_file: 入口文件，默认 index.html
            enable_gzip: 是否启用 Gzip 压缩
            enable_cache: 是否启用静态资源缓存
            cache_max_age: 缓存最大天数
            ssl_cert_path: SSL 证书路径（可选）
            ssl_key_path: SSL 私钥路径（可选）
            ssl_port: HTTPS 端口，默认 443
            redirect_http_to_https: 是否将 HTTP 重定向到 HTTPS
            proxy_pass: 反向代理地址（可选，用于 SPA 路由）
            custom_config: 自定义配置内容（可选）

        Returns:
            tuple[bool, str]: (是否成功, 消息)
        """
        try:
            if not self.ssh_tool.is_connected():
                if not self.ssh_tool.connect():
                    return False, "SSH 连接失败"

            root_path = root_path or deploy_path
            config_filename = f"{server_name.replace('.', '_')}.conf"
            remote_config_path = f"{nginx_config_path}/{config_filename}"

            # 生成 Nginx 配置
            nginx_config = self._generate_nginx_config(
                server_name=server_name,
                root_path=root_path,
                port=port,
                index_file=index_file,
                enable_gzip=enable_gzip,
                enable_cache=enable_cache,
                cache_max_age=cache_max_age,
                ssl_cert_path=ssl_cert_path,
                ssl_key_path=ssl_key_path,
                ssl_port=ssl_port,
                redirect_http_to_https=redirect_http_to_https,
                proxy_pass=proxy_pass,
                custom_config=custom_config,
            )

            # 创建临时文件写入配置
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False, encoding="utf-8") as f:
                f.write(nginx_config)
                temp_config_path = f.name

            try:
                # 上传配置文件
                if not self.ssh_tool.upload_file(temp_config_path, remote_config_path, create_dirs=True):
                    return False, f"上传 Nginx 配置文件失败: {remote_config_path}"

                # 测试 Nginx 配置
                success, output = self.ssh_tool.run_cmd("nginx -t")
                if not success:
                    logger.warning(f"Nginx 配置测试失败: {output}")
                    return False, f"Nginx 配置测试失败: {output}"

                # 重载 Nginx
                success, output = self.ssh_tool.run_cmd("nginx -s reload || systemctl reload nginx")
                if not success:
                    logger.warning(f"Nginx 重载失败: {output}，请手动检查配置")

                logger.info(f"Nginx 配置成功: {remote_config_path}")
                return True, f"Nginx 配置成功: {remote_config_path}"

            finally:
                # 清理临时文件
                try:
                    os.unlink(temp_config_path)
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"配置 Nginx 失败: {e}")
            return False, f"配置 Nginx 失败: {str(e)}"

    def _generate_nginx_config(
        self,
        server_name: str,
        root_path: str,
        port: int,
        index_file: str,
        enable_gzip: bool,
        enable_cache: bool,
        cache_max_age: int,
        ssl_cert_path: str | None,
        ssl_key_path: str | None,
        ssl_port: int,
        redirect_http_to_https: bool,
        proxy_pass: str | None,
        custom_config: str | None,
    ) -> str:
        """生成 Nginx 配置文件内容"""
        config_lines = []

        # HTTP 服务器块
        if redirect_http_to_https and ssl_cert_path:
            # HTTP 重定向到 HTTPS
            config_lines.append(f"server {{")
            config_lines.append(f"    listen {port};")
            config_lines.append(f"    server_name {server_name};")
            config_lines.append(f"    return 301 https://$server_name$request_uri;")
            config_lines.append(f"}}")
            config_lines.append("")

        # HTTPS 服务器块（如果有 SSL）
        if ssl_cert_path and ssl_key_path:
            config_lines.append(f"server {{")
            config_lines.append(f"    listen {ssl_port} ssl http2;")
            config_lines.append(f"    server_name {server_name};")
            config_lines.append("")
            config_lines.append(f"    ssl_certificate {ssl_cert_path};")
            config_lines.append(f"    ssl_certificate_key {ssl_key_path};")
            config_lines.append("    ssl_protocols TLSv1.2 TLSv1.3;")
            config_lines.append("    ssl_ciphers HIGH:!aNULL:!MD5;")
            config_lines.append("")
        else:
            # HTTP 服务器块
            config_lines.append(f"server {{")
            config_lines.append(f"    listen {port};")
            config_lines.append(f"    server_name {server_name};")
            config_lines.append("")

        # 网站根目录
        config_lines.append(f"    root {root_path};")
        config_lines.append(f"    index {index_file};")
        config_lines.append("")

        # Gzip 压缩
        if enable_gzip:
            config_lines.append("    # Gzip 压缩")
            config_lines.append("    gzip on;")
            config_lines.append("    gzip_vary on;")
            config_lines.append("    gzip_min_length 1024;")
            config_lines.append(
                "    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;"
            )
            config_lines.append("")

        # 静态资源缓存
        if enable_cache:
            config_lines.append("    # 静态资源缓存")
            config_lines.append("    location ~* \\.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {")
            config_lines.append(f"        expires {cache_max_age}d;")
            config_lines.append('        add_header Cache-Control "public, immutable";')
            config_lines.append("    }")
            config_lines.append("")

        # SPA 路由支持（Vue Router / React Router）
        if proxy_pass:
            config_lines.append("    # API 代理")
            config_lines.append(f"    location /api/ {{")
            config_lines.append(f"        proxy_pass {proxy_pass};")
            config_lines.append("        proxy_set_header Host $host;")
            config_lines.append("        proxy_set_header X-Real-IP $remote_addr;")
            config_lines.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
            config_lines.append("        proxy_set_header X-Forwarded-Proto $scheme;")
            config_lines.append("    }")
            config_lines.append("")

        # SPA 路由支持（所有请求都返回 index.html）
        config_lines.append("    # SPA 路由支持")
        config_lines.append("    location / {")
        config_lines.append("        try_files $uri $uri/ /index.html;")
        config_lines.append("    }")
        config_lines.append("")

        # 自定义配置
        if custom_config:
            config_lines.append("    # 自定义配置")
            config_lines.append(custom_config)
            config_lines.append("")

        config_lines.append("}")

        return "\n".join(config_lines)

    def rollback(self, remote_deploy_path: str, backup_suffix: str | None = None) -> tuple[bool, str]:
        """回滚到备份版本

        Args:
            remote_deploy_path: 部署路径
            backup_suffix: 备份后缀，如果不提供则查找最新的备份

        Returns:
            tuple[bool, str]: (是否成功, 消息)
        """
        try:
            if not self.ssh_tool.is_connected():
                if not self.ssh_tool.connect():
                    return False, "SSH 连接失败"

            # 查找备份
            if backup_suffix:
                backup_path = f"{remote_deploy_path}_backup_{backup_suffix}"
            else:
                # 查找最新的备份
                success, output = self.ssh_tool.run_cmd(f"ls -td {remote_deploy_path}_backup_* 2>/dev/null | head -1")
                if not success or not output.strip():
                    return False, "未找到备份版本"
                backup_path = output.strip()

            if not self.ssh_tool.path_exists(backup_path):
                return False, f"备份路径不存在: {backup_path}"

            # 备份当前版本
            current_backup = f"{remote_deploy_path}_backup_before_rollback_{int(time.time())}"
            if self.ssh_tool.path_exists(remote_deploy_path):
                if not self.ssh_tool.rename(remote_deploy_path, current_backup):
                    logger.warning("备份当前版本失败，继续回滚")

            # 恢复备份
            if self.ssh_tool.rename(backup_path, remote_deploy_path):
                logger.info(f"回滚成功: {backup_path} -> {remote_deploy_path}")
                return True, f"回滚成功到 {backup_path}"
            else:
                return False, f"回滚失败: 无法恢复 {backup_path}"

        except Exception as e:
            logger.error(f"回滚失败: {e}")
            return False, f"回滚失败: {str(e)}"

    def list_backups(self, remote_deploy_path: str) -> tuple[bool, list[str]]:
        """列出所有备份版本

        Args:
            remote_deploy_path: 部署路径

        Returns:
            tuple[bool, list[str]]: (是否成功, 备份列表)
        """
        try:
            if not self.ssh_tool.is_connected():
                if not self.ssh_tool.connect():
                    return False, []

            success, output = self.ssh_tool.run_cmd(f"ls -td {remote_deploy_path}_backup_* 2>/dev/null")
            if not success:
                return True, []

            backups = [line.strip() for line in output.strip().split("\n") if line.strip()]
            return True, backups

        except Exception as e:
            logger.error(f"列出备份失败: {e}")
            return False, []
