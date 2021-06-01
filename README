# Z-Journal

---

## Introduction

---

File system journaling critically limits the scalability of a file system because all simultaneous write operations coming from multiple cores must be serialized to be written to the journal area. Although a few scalable journaling approaches have been proposed, they required the radical redesign of file systems, or tackled only a part of the scalability bottlenecks. Per-core journaling, in which a core has its own journal stack, can clearly provide scalability. However, it requires a journal coherence mechanism because two or more cores can write to a shared file system block, so write order on the shared block must be preserved across multiple journals. In this paper, we propose a novel scalable per-core journal design. The proposed design allows a core to commit independently to other cores. The journal transactions involved in shared blocks are linked together through order-preserving transaction chaining to form a transaction order graph. The ordering constraints later will be imposed during the checkpoint process. Because the proposed design is self-contained in the journal layer and does not rely on the file system, its implementation, Z-Journal, can easily replace JBD2, the generic journal layer. Our evaluation with FxMark, SysBench and Filebench running on the ext4 file system in an 80-core server showed that it outperformed the current JBD2 by up to approx. 4000 %.

## The guide to using Z-Journal

---

- Download and build e2fsprocs for zjournal.

```
git clone https://github.com/J-S-Kim/e2fsprog-zj.git
cd e2fsprog-zj
./configure
make
```

- Download and install the kernel of the current repository, and reboot to the kernel you installed.
- When installing, configure should be set as below.
- After rebooting, verify that ext4mj and zj modules are installed successfully.

```
File systems  --->
    [M] The Extended 4 (ext4mj) filesystem
```

- Format the storage device and mount it with the command shown below.
- At this point, the number of journals is the same as the current number of online cores.

```
sudo ./e2fsprog-zj/misc/mke2fs -t ext4 -J multi_journal -F -G 1 /dev/<block device>
sudo mount -t ext4mj /dev/<block device> <mount point>
```

## Publication

---
