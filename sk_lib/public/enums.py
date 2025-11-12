from enum import Enum


class LinuxSoft(Enum):
    """Linux软件"""

    DMIDECODE = "dmidecode"
    NGINX = "nginx"


class OsPlatform(Enum):
    """OS系统"""

    Centos = "centos"
