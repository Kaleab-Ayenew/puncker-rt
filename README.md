# Puncker: The Python OCI Container Runtime

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![OCI Compliant](https://img.shields.io/badge/OCI-Compliant-green)](https://opencontainers.org/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey)]()

**Puncker** is an educational, OCI-compliant container runtime written in pure Python. 

It is designed to replace `runc` in the Docker stack to demonstrate exactly how containers work under the hood. It uses `ctypes` to interact directly with Linux system calls (`unshare`, `mount`, `pivot_root`, `execve`), making the "black magic" of containerization readable and understandable.

**Goal:** To demystify container internals for developers who find Go or C implementations of `runc` difficult to parse.

---

## 🧠 How It Works

Puncker implements the [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec). It acts as a translation layer between a JSON configuration and the Linux Kernel.

### The "Magic" Explained

Unlike high-level libraries, Puncker talks directly to the kernel. Here are the core concepts implemented in this repo:

1.  **Namespaces (`unshare`)**: We use `ctypes` to call `libc.unshare`. This gives the process its own private view of the system (PID, Mounts, Network, Users).
2.  **The Filesystem Dance (`pivot_root`)**:
    *   We mark the mount propagation as `MS_PRIVATE` to disconnect from the host.
    *   We bind-mount the rootfs to itself (a kernel requirement).
    *   We call `syscall(155)` (`pivot_root`) to swap the OS root with our container root.
3.  **Capabilities**: We use `libcap` to drop dangerous root privileges (like loading kernel modules) before executing the user code.
4.  **Cgroups V2**: We manipulate the `/sys/fs/cgroup` filesystem to apply resource limits (RAM/CPU) to the process.

---

## 🚀 Installation & Usage

### Prerequisites
*   Linux (Kernel 5.x+, Cgroup v2 recommended)
*   Python 3.13+
*   Docker (to act as the manager)

### 1. Install Puncker
Clone the repo and install the binary.

```bash
git clone https://github.com/yourusername/puncker.git
cd puncker/runtime
pip install .
```

This will install the `puncker` command to your path. Verify it with:
```bash
sudo puncker --help
```

### 2. Configure Docker
Tell Docker that a new runtime exists. Edit `/etc/docker/daemon.json`:

```json
{
    "runtimes": {
        "puncker": {
            "path": "/usr/local/bin/puncker"
        }
    }
}
```
*Note: Ensure the path matches where `pip` installed the binary (e.g., `/usr/local/bin/puncker` or `/usr/bin/puncker`).*

Restart Docker:
```bash
sudo systemctl restart docker
```

### 3. Run Your First Container
You can now use the standard Docker CLI, but swap the engine!

```bash
# Run Hello World
sudo docker run --runtime=puncker --rm hello-world

# Run an interactive shell (No TTY support yet, use -i)
sudo docker run --runtime=puncker -i --rm ubuntu bash
```

---

## 📂 Project Structure

The codebase is designed to be read top-to-bottom.

*   **`src/main.py`**: The entry point. Handles CLI arguments (`create`, `start`, `delete`) and orchestrates the lifecycle.
*   **`src/constants.py`**: Maps Linux C headers (`<sched.h>`, `<sys/mount.h>`) to Python constants.
*   **`src/errors.py`**: Custom error handling.

### Key Code Snippets

**The Isolation (Namespaces):**
```python
# From src/main.py
libc.unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC)
```

**The Jail (Pivot Root):**
```python
# From src/main.py
libc.mount(None, "/", None, MS_REC | MS_PRIVATE, None)
libc.mount(root_path, root_path, None, MS_BIND, None)
libc.syscall(155, ".", "old_root") # 155 is pivot_root on x86_64
os.chdir("/")
libc.umount2("old_root", MNT_DETACH)
```

---

## 🛠️ Development & Debugging

If the container fails to start, Docker often hides the error. Puncker logs everything to a debug file.

1.  **View Logs:**
    ```bash
    tail -f /tmp/puncker-debug.log
    ```

2.  **Manual Testing (Without Docker):**
    You can run OCI bundles manually to test the runtime.
    ```bash
    # 1. Create a bundle
    mkdir -p bundle/rootfs
    docker export $(docker create alpine) | tar -C bundle/rootfs -xvf -
    
    # 2. Generate config
    runc spec -b bundle
    
    # 3. Run
    sudo puncker create my-container --bundle bundle
    sudo puncker start my-container
    sudo puncker delete my-container
    ```

---

## ⚠️ Current Limitations (Roadmap)

This is a learning project, not a production security tool.

*   [x] Basic Lifecycle (Create, Start, Kill, Delete)
*   [x] Filesystem Isolation (Pivot Root)
*   [x] Proc/Sysfs/Tmpfs Mounting
*   [x] Docker Integration
*   [x] User Namespaces (UID/GID Mapping)
*   [x] Capabilities (Dropping Privileges)
*   [ ] **TTY Support:** `docker run -t` (Console Sockets) is not yet implemented.
*   [ ] **Seccomp:** System call filtering is missing.
*   [ ] **Cgroups v1:** Only Cgroups v2 is currently supported.

---

## 🤝 Contributing

This project is part of the "Build Your Own X" movement. If you want to add a feature (like TTY support or Seccomp), feel free to open a PR!

1.  Fork the repo
2.  Create your feature branch (`git checkout -b feature/tty-support`)
3.  Commit your changes
4.  Push to the branch
5.  Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.