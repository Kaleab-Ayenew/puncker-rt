import argparse
from pathlib import Path
import sys
import os
import json
import ctypes
import shutil
import logging
import errno
from datetime import datetime
from typing import Literal
from src.constants import COMMON_LIBC_FLAGS as uflags, TIME_FLAGS
from src.constants import CONFIG_FLAG_MAP as flag_map
from src.constants import MOUNT_FLAG_MAPS as mnt_flags
from src.constants import FEATURES_JSON
from src.errors import ContainerExistsError

libc = ctypes.CDLL('libc.so.6', use_errno=True)

# Setup logging to a temp file
logging.basicConfig(
    filename='/tmp/puncker-debug.log',
    level=logging.DEBUG,
    format='%(asctime)s [%(process)d] %(levelname)s: %(message)s'
)

REAL_STDERR = sys.stderr
sys.stderr = open("/tmp/puncker-debug.log", "a")
REAL_STDOUT = sys.stdout
sys.stdout = open("/tmp/puncker-debug.log", "a")


def parse_env_vars(env_list: list):
    env_dict = {}
    for e in env_list:
        name, val = e.split("=")[0], e.split("=")[1]
        env_dict[name] = val
    return env_dict

def parse_oci_config(config_path: str):
    with open(config_path, "r") as f:
        parsed_config = json.load(f)
    return parsed_config

def rm_dir(path: str):
    try:
        shutil.rmtree(path)
    except OSError as e:
        print(f"Error: {e.filename} - {e.strerror}.", flush=True)

def perform_mount_sequence(oci_config, root_path):
    # Mount the filesystems specified in the config
    for m in oci_config["mounts"]:
        if m["type"] == "cgroup":
            continue
        options = m.get("options", [])
        m_flags = 0
        m_data = []

        for o in options:
            if o in mnt_flags:
                m_flags |= mnt_flags[o]
            elif o not in TIME_FLAGS:
                m_data.append(o)

        


        m_src = m.get("source", "").encode("utf-8")
        m_trgt: str = m.get("destination", "")
        if m_trgt.startswith("/"):
            m_trgt = m_trgt.lstrip("/")
        m_trgt_abs = os.path.join(root_path, m_trgt).encode("utf-8")
        if m_src.decode() and Path(m_src.decode()).is_file():
            os.makedirs(Path(m_trgt_abs.decode()).parent, exist_ok=True)
            with open(m_trgt_abs.decode(), "w") as f:
                print("Creating ", m_trgt_abs.decode(), flush=True)
                pass
        else:
            os.makedirs(m_trgt_abs.decode(), exist_ok=True)
        m_type = m.get("type", "").encode("utf-8")

        data_str = ",".join(m_data)

        is_readonly = (m_flags & uflags.MS_RDONLY)

        if is_readonly and m_type.decode() != "bind":
            initial_flags = m_flags & ~uflags.MS_RDONLY
        else:
            initial_flags = m_flags

        
        is_bind_flag = (initial_flags & uflags.MS_BIND)
        is_bind_type = (m_type.decode() == "bind")

        # Try to unmount to prevent duplicate mounts
        libc.umount2(ctypes.c_char_p(m_trgt_abs), 2)
        # Set fs_type_arg to None for bind mount
        if is_bind_flag or is_bind_type:
            print("[*] Bind operation confiremed")
            initial_flags |= uflags.MS_BIND
            fs_type_arg = None
            data_arg = None
        else:
            print(f"[*] Not a bind opearation: {m_type}")
            fs_type_arg = ctypes.c_char_p(m_type)
            data_arg = ctypes.c_char_p(data_str.encode("utf-8"))
        # Perform the mount
        ret = libc.mount(
            ctypes.c_char_p(m_src),
            ctypes.c_char_p(m_trgt_abs),  
            fs_type_arg,
            ctypes.c_ulong(initial_flags),      
            data_arg
        )

        if ret <0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"Failed to perform {m_type} mount from {m_src} to {m_trgt}: {os.strerror(errno)}")


        if is_readonly:
            remount_flags = uflags.MS_REMOUNT | uflags.MS_BIND | m_flags
        
            ret = libc.mount(
                None, # Source is ignored for remount
                ctypes.c_char_p(m_trgt_abs),
                None,
                ctypes.c_ulong(remount_flags),
                None
            )
        
        if ret < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"Failed to remount {m_trgt} RO: {os.strerror(errno)}")

def is_pid_alive(pid: int):
    try:
        os.kill(pid, 0)
        return True
    except OSError as e:
        if e.errno == errno.ESRCH: # No such process
            return False
        elif e.errno == errno.EPERM: # Permission denied
            return True


def get_cgroup_path(oci_config: dict, container_id: str):
    cgroup_base = "/sys/fs/cgroup"
    cgroup_path = oci_config["linux"].get("cgroupsPath", f"puncker-rt/{container_id}")
    if not Path(cgroup_path).is_absolute():
        cgroup_path = os.path.join(cgroup_base, cgroup_path)
    return cgroup_path


def apply_cgroup_limits(oci_config, cgroup_path):
    linux_data : dict = oci_config["linux"]

    if linux_data.get("resources"):
        os.makedirs(cgroup_path, exist_ok=True)
        if mem_cg := linux_data.get("resources").get("memory"):
            for c in mem_cg:
                sfx = {"limit":"max", "reservation":"low", "swap":"swap.max"}
                with open(os.path.join(cgroup_path, f"memory.{sfx[c]}"), "w") as f:
                    f.write(str(mem_cg[c]))

        if cpu_cg := linux_data.get("resources").get("cpu"):
            for c in cpu_cg:
                if c == "shares":
                    with open(os.path.join(cgroup_path, "cpu.weight"), "w") as f:
                        f.write(str(cpu_cg[c]))
                elif c == "quota":
                    with open(os.path.join(cgroup_path, "cpu.max"), "w") as f:
                        f.write(f"{cpu_cg[c]} {cpu_cg['period']}")
                elif c == "cpus":
                    with open(os.path.join(cgroup_path, "cpuset.cpus"), "w") as f:
                        f.write(str(cpu_cg[c]))

        if pid_cg := linux_data.get("resources").get("pids"):
            with open(os.path.join(cgroup_path, f"pids.max"), "w") as f:
                f.write(str(pid_cg.get("limit", "")))

def clean_up(container_id: str, oci_config: str):
    dir_path = f"/run/puncker-rt/{container_id}"
    cgroup_path = get_cgroup_path(oci_config, container_id)
    if os.path.exists(dir_path):
        rm_dir(dir_path) # Remove state dir
    if os.path.exists(cgroup_path):
        rm_dir(cgroup_path) # Remove the cgroup dir


def create(container_id: str, bundle_path: str, mode: Literal["foreground", "detached"] = "foreground", pid_file=None):
    os.makedirs(f"/run/puncker-rt", exist_ok=True)
    existing_containers = os.listdir("/run/puncker-rt/")
    if container_id in existing_containers:
        raise ContainerExistsError(f"Container with id: {container_id} already exists.")
    oci_config = parse_oci_config(os.path.join(bundle_path, "config.json"))
    process_data = oci_config["process"]
    fs_data = oci_config["root"]
    linux_data : dict = oci_config["linux"]
    root_path = os.path.join(bundle_path, fs_data['path'])

    # Create container tracking directory
    container_state_dir = f"/run/puncker-rt/{container_id}"
    os.makedirs(container_state_dir, exist_ok=True)

    # Create the state.json file
    with open(os.path.join(container_state_dir, "state.json"), "w") as f:
        initial_state = {
            "ociVersion": "1.2.0",
            "id": container_id,
            "pid": 0,
            "status": "creating",
            "bundle": os.path.abspath(bundle_path),
            "rootfs": os.path.join(os.path.abspath(bundle_path), oci_config["root"]["path"])
        }
        json.dump(initial_state, f, indent=2)

    try:
        os.mkfifo(os.path.join(container_state_dir, "exec.fifo"), 0o600)
        print(f"Created exec.fifo file for container id: {container_id}", flush=True)
    except FileExistsError:
        print("exec.fifo already exists", flush=True)

    # Prepare an old_root directory for the pivot root
    os.makedirs(os.path.join(root_path, "old_root"), exist_ok=True)


    # Apply Cgroup limits if any
    cgroup_path = get_cgroup_path(oci_config, container_id)
    apply_cgroup_limits(oci_config, cgroup_path)

    # Unshare PID to make sure the forked process enters a new process namespace
    for ns in linux_data["namespaces"]:
        if ns["type"] == "pid":
            libc.unshare(flag_map["pid"] )


    # Sync pipe
    sync_pipe_rd, sync_pipe_wr = os.pipe()
    
    # Fork the child process
    child_pid = os.fork()
    if child_pid == 0:
        os.close(sync_pipe_rd) # Close the read end of the sync pipe

        # Ready the flags for the unshare system call
        final_unshare_flag = 0
        for ns in linux_data["namespaces"]:
            if ns["type"] == "pid":
                continue
            elif ns["type"] == "user":
                if not linux_data.get("uidMappings") or not linux_data.get("gidMappings"):
                    cgroup_path = f"/sys/fs/cgroup/puncker-rt/{container_id}"
                    rm_dir(cgroup_path) # Remove the Cgroup dir, and exit the process
                    raise ValueError("You must specify uidMappings, and gidMappings if user namespace was used.")
            final_unshare_flag = final_unshare_flag | flag_map[ns['type']]

        # Use unshare syscall to perform process isolation
        libc.unshare(final_unshare_flag)


        # Convert the rootfs directory to a mountpoint to fullfill the requirement for pivot root
        libc.mount(None, "/", None, uflags.MS_REC | uflags.MS_PRIVATE, None) # Set mount propagation to private so that mounts in this namespace don't cross over to the parent namespace
        libc.mount(root_path.encode("utf-8"), root_path.encode("utf-8"), None, uflags.MS_BIND, None)

        # Perform mount sequence based on the configs listed in the OCI config file
        perform_mount_sequence(oci_config, root_path)

        # Chdir to the rootpath
        os.chdir(root_path)

        # Get the fifo file descriptor before Pivot Root
        fifo_fd = os.open(
                f"/run/puncker-rt/{container_id}/exec.fifo", 
                os.O_RDWR
            )

        # Performing Pivot root - BEWARE: BEYOND THIS IS A FILESYSTEM CAGE
        syscall_num = 155
        ret = libc.syscall(syscall_num, ".".encode("utf-8"), "./old_root".encode("utf-8")) # pivot root sys call
        if ret != 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"pivot_root failed: {os.strerror(errno)}")
            
        os.chdir("/")
        # Unmount the old root
        libc.umount2("old_root".encode(), 2) # 2 is MNT_DETACH
        os.rmdir("./old_root")
        
        # Remount as read only if the readOnly is set to true
        if oci_config.get("root").get("readonly"):
            ret = libc.mount(b"/", b"/", None, uflags.MS_REMOUNT | uflags.MS_BIND | uflags.MS_RDONLY, None)
            if ret < 0:
                errno = ctypes.get_errno()
                raise OSError(errno, f"Failed to remount root as read-only: {os.strerror(errno)}")

        command = process_data['args'][0]
        
        args = process_data['args']
        env_vars = parse_env_vars(process_data['env'])
        executable_path = shutil.which(command, path=env_vars["PATH"])

        os.chdir(process_data["cwd"])
        print("Blocking untill somebody writes to the exec.fifo file", flush=True)
        os.write(sync_pipe_wr, b"0")
        os.read(fifo_fd, 1)
        os.close(fifo_fd)
        print("I have been called from my sleep. Lets do this!", flush=True)

        # Set the process uid and gid
        os.setgid(process_data['user']['gid'])
        os.setuid(process_data['user']['uid'])

        # The first argument in the list must be the command name itself.
        os.execve(executable_path, args, env_vars)

        
    else:
        os.close(sync_pipe_wr)
        print("Hello from the parent")

        # Wait till the child says it is done creating the container
        data = os.read(sync_pipe_rd, 1)
        if not data:
            raise ValueError("The sync pipe was empty")

        # Write the pid to the pid file if specified
        if pid_file:
            with open(pid_file, "w") as f:
                f.write(str(child_pid))
        
        # Add the child process to Cgroups
        with open(os.path.join(cgroup_path, "cgroup.procs"), "w") as f:
            f.write(str(child_pid))
        
        # Perform User and Group id mapping
        if "user" in [ns["type"] for ns in linux_data["namespaces"]]:
            os.makedirs(f"/procs/{child_pid}/", exist_ok=True)
            with open(f"/procs/{child_pid}/uid_map", "w") as f:
                uid_data = "\n".join([f"{m['containerID']} {m['hostID']} {m['size']}" for m in linux_data.get("uidMappings")])
                f.write(uid_data)
            
            with open(f"/procs/{child_pid}/gid_map", "w") as f:
                gid_data = "\n".join([f"{m['containerID']} {m['hostID']} {m['size']}" for m in linux_data.get("gidMappings")])
                f.write(gid_data)
        
        
        # Create the state.json file
        with open(os.path.join(container_state_dir, "state.json"), "w") as f:
            state_data = {
                "ociVersion": "1.2.0",
                "id": container_id,
                "pid": child_pid,
                "status": "created",
                "bundle": os.path.abspath(bundle_path),
                "rootfs": os.path.join(os.path.abspath(bundle_path), oci_config["root"]["path"]),
                "created": datetime.now().isoformat()
                }
            json.dump(state_data, f, indent=2)

        if mode == "foreground":
            _, status = os.waitpid(child_pid, 0)
            print(f"Container exited with status {status}", flush=True)
            sys.exit(status)



def start(container_id: str):
    if container_id not in os.listdir("/run/puncker-rt/"):
        raise ValueError(f"Couldn't find container with id: {container_id}")
    container_state_dir = f"/run/puncker-rt/{container_id}"
    print(f"Bringing the container with id {container_id} up.", flush=True)
    with open(os.path.join(container_state_dir, "exec.fifo"), "w") as f:
        f.write("1")
    # Update the state.json file
    with open(os.path.join(container_state_dir, "state.json"), "r+") as f:
        state_data = json.load(f)
        f.seek(0)
        state_data["status"] = "running"
        json.dump(state_data, f, indent=2)
        f.truncate()

    

def state(container_id: str, pr_std=True):
    if container_id not in os.listdir("/run/puncker-rt/"):
        raise ValueError(f"Couldn't find container with id: {container_id}")

    container_state_dir = f"/run/puncker-rt/{container_id}"
    with open(os.path.join(container_state_dir, "state.json"), "r+") as f:
        parsed_data = json.load(f)
        if not is_pid_alive(int(parsed_data["pid"])):
            f.seek(0)
            parsed_data["status"] = "stopped"
            parsed_data["pid"] = 0
            json.dump(parsed_data, f, indent=2)
            f.truncate()
    if pr_std:
        print(parsed_data, file=REAL_STDOUT, flush=True)
    return parsed_data



def delete(container_id: str, force=False):
    if container_id not in os.listdir("/run/puncker-rt/"):
        raise ValueError(f"Couldn't find container with id: {container_id}")
    state_data = state(container_id, pr_std=False)
    if not force and state_data["status"] != "stopped":
        raise ValueError("Please stop the container before trying to delete it.")
    oci_config = parse_oci_config(os.path.join(state_data["bundle"], "config.json"))
    clean_up(container_id, oci_config) # Perform cleanup
    print(f"[*] Removed container with id: {container_id}.")
    sys.exit(0)


def kill(container_id: str, signal: str | None = None):
    if container_id not in os.listdir("/run/puncker-rt/"):
        raise ValueError(f"Couldn't find container with id: {container_id}")

    state_dir = f"/run/puncker-rt/{container_id}"

    with open(os.path.join(state_dir, "state.json")) as f:
        state_data = json.load(f)

    if state_data["status"] not in ["running", "created"]:
        raise ValueError("You can't kill a container that is neither created nor running")

    if not signal:
        os.kill(state_data["pid"], 15)
    elif signal in ["SIGKILL", "KILL", "9"]:
        os.kill(state_data["pid"], 9)
    elif signal in ["SIGTERM", "TERM", "15"]:
        os.kill(state_data["pid"], 15)
    elif signal in ["SIGUSR1", "USR1", "10"]:
        os.kill(state_data["pid"], 10)
    print(f"Killed container with id: {container_id}, pid: {state_data['pid']}")
    
    # Update the state.json file
    with open(os.path.join(state_dir, "state.json"), "r+") as f:
        state_data = json.load(f)
        f.seek(0)
        state_data["status"] = "stopped"
        state_data["pid"] = 0
        json.dump(state_data, f, indent=2)
        f.truncate()

def features():
    print(FEATURES_JSON, flush=True)


def main():
    print(sys.argv)
    parser = argparse.ArgumentParser(description="Puncker container runtime")

    parser.add_argument("--root", help="Root directory for storage of container state (Ignored)")
    parser.add_argument("--log", help="Path to the log file (Ignored)")
    parser.add_argument("--log-format", help="Log format (json/text) (Ignored)")
    parser.add_argument("--systemd-cgroup", action="store_true", help="Enable systemd cgroup (Ignored)")


    subparser = parser.add_subparsers(dest="command", required=True)

    create_parser = subparser.add_parser("create", help="Create a container")
    create_parser.add_argument("container_id", help="A Unique ID for the container")
    create_parser.add_argument("--bundle", required=True, help="Path to bundle")
    create_parser.add_argument("--pid-file", help="Path to the PID file")
    create_parser.add_argument("--console-socket", help="UNIX socket for TTY master")
    create_parser.add_argument("--no-pivot", action="store_true", help="Do not use pivot_root")

    start_parser = subparser.add_parser("start", help="Start a created container")
    start_parser.add_argument("container_id", help="The unique id of the created container")

    state_parser = subparser.add_parser("state", help="Get container state")
    state_parser.add_argument("container_id", help="Unique ID of the container")

    delete_parser = subparser.add_parser("delete", help="Delete a container")
    delete_parser.add_argument("container_id", help="Unique ID of the container")
    delete_parser.add_argument("--force", action="store_true", help="Force delete running container")

    kill_parser = subparser.add_parser("kill", help="Kill a container")
    kill_parser.add_argument("container_id", help="The unique id of the container to kill")
    kill_parser.add_argument("signal", nargs="?", default="SIGTERM", help="The signal to send")

    features_parser = subparser.add_parser("features", help="A list of supported features in JSON format")



    c_args, unknown = parser.parse_known_args()
    if unknown:
        sys.stderr.write(f"Warning: Ignoring unknown args: {unknown}\n")


    if c_args.command == "create":
        try:
            create(c_args.container_id, c_args.bundle, "detached", c_args.pid_file)
        except ContainerExistsError as e:
            raise e
        except Exception as e:
            clean_up(c_args.container_id, parse_oci_config(os.path.join(c_args.bundle, "config.json")))
            raise(e)

    elif c_args.command == "start":
        start(c_args.container_id)
    elif c_args.command == "state":
        state(c_args.container_id)
    elif c_args.command == "delete":
        print("Force command looks like this:", c_args.force)
        delete(c_args.container_id, force=c_args.force)
    elif c_args.command == "kill":
        kill(c_args.container_id)
    elif c_args.command == "features":
        features()



if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
        sys.stderr.flush()
        print("Runtime Error! Check /tmp/puncker-debug.log for details.\n", file=REAL_STDOUT, flush=True)
