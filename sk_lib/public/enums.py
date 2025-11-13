from enum import Enum


class Soft(Enum):
    """Linux软件"""

    DMIDECODE = "dmidecode"
    NGINX = "nginx"
    PYENV = "pyenv"
    NVM = "nvm"
    GIT = "git"


class OsPlatform(Enum):
    """OS系统"""

    Centos = "centos"
