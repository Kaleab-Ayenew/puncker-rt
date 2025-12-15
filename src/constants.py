from dataclasses import dataclass

@dataclass(frozen=True)
class CommonFlags:
    """Constants for Linux unshare flags used in namespace isolation."""
    CLONE_NEWNS: int = 0x00020000      # Mount namespace (filesystem)
    CLONE_NEWUTS: int = 0x04000000     # UTS namespace (hostname)
    CLONE_NEWIPC: int = 0x08000000     # IPC namespace
    CLONE_NEWUSER: int = 0x10000000    # User namespace
    CLONE_NEWPID: int = 0x20000000     # PID namespace
    CLONE_NEWNET: int = 0x40000000     # Network namespace
    CLONE_NEWCGROUP: int = 0x02000000  # Cgroup namespace
    MS_REC: int = 0x4000 # Recursive mounts
    MS_PRIVATE: int = 0x40000 # Mount private
    MS_BIND: int = 0x1000 # Bind mount
    MS_REMOUNT: int = 0x20 # Alter flags of a mounted FS
    MS_RDONLY: int = 0x1 # Read-only
    MS_NOSUID: int = 0x2 
    MS_NODEV: int = 0x4
    MS_NOEXEC: int = 0x8
    MS_RELATIME  : int  = 0x200000
    MS_STRICTATIME: int = 0x1000000


COMMON_LIBC_FLAGS = CommonFlags()

CONFIG_FLAG_MAP = {
				"pid": COMMON_LIBC_FLAGS.CLONE_NEWPID,
				"network": COMMON_LIBC_FLAGS.CLONE_NEWNET,
				"ipc": COMMON_LIBC_FLAGS.CLONE_NEWIPC,
				"uts": COMMON_LIBC_FLAGS.CLONE_NEWUTS,
				"mount": COMMON_LIBC_FLAGS.CLONE_NEWNS,
				"cgroup": COMMON_LIBC_FLAGS.CLONE_NEWCGROUP,
                "user": COMMON_LIBC_FLAGS.CLONE_NEWUSER
}

MOUNT_FLAG_MAPS = {
    "ro":          COMMON_LIBC_FLAGS.MS_RDONLY,
    "rw":          0, # Default, no flag needed
    "nosuid":      COMMON_LIBC_FLAGS.MS_NOSUID,
    "nodev":       COMMON_LIBC_FLAGS.MS_NODEV,
    "noexec":      COMMON_LIBC_FLAGS.MS_NOEXEC,
    "bind": COMMON_LIBC_FLAGS.MS_BIND
    # "relatime":    COMMON_LIBC_FLAGS.MS_RELATIME,
    # "strictatime": COMMON_LIBC_FLAGS.MS_STRICTATIME
}

TIME_FLAGS = ["relatime", "strictatime"]


FEATURES_JSON = """{
    "ociVersionMin": "1.0.0",
    "ociVersionMax": "1.1.0",
    "os": "linux",
    "arch": "amd64",
    "annotations": {
        "org.opencontainers.runtime-spec.features.mounts.volumemounts": true,
        "org.opencontainers.runtime-spec.features.mounts.bind": true,
        "org.opencontainers.runtime-spec.features.process.user": true,
        "org.opencontainers.runtime-spec.features.process.terminal": false
    },
    "mounts": [
        {
            "driver": "proc",
            "options": ["rw", "nosuid", "nodev", "noexec", "relatime"]
        },
        {
            "driver": "tmpfs",
            "options": ["rw", "nosuid", "nodev", "noexec", "relatime", "mode", "size"]
        },
        {
            "driver": "sysfs",
            "options": ["ro", "rw", "nosuid", "nodev", "noexec"]
        },
        {
            "driver": "bind",
            "options": ["ro", "rw", "bind", "rbind"]
        },
        {
            "driver": "devpts",
            "options": ["rw", "nosuid", "noexec", "newinstance", "ptmxmode", "mode", "gid"]
        },
        {
            "driver": "mqueue",
            "options": ["rw", "nosuid", "nodev", "noexec"]
        }
    ],
    "linux": {
        "namespaces": [
            "pid",
            "network",
            "mount",
            "ipc",
            "uts",
            "user"
        ],
        "capabilities": {
            "enabled": false,
            "known": []
        },
        "cgroups": {
            "enabled": false,
            "v1": false,
            "v2": false
        },
        "seccomp": {
            "enabled": false
        },
        "apparmor": {
            "enabled": false
        },
        "selinux": {
            "enabled": false
        },
        "intelRdt": {
            "enabled": false
        }
    }
}"""