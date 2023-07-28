/*
Copyright 2022 The Kuasar Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use std::{
    os::unix::{
        io::RawFd,
        prelude::{AsRawFd, FromRawFd, OwnedFd},
    },
    path::Path,
    time::Duration,
};

use anyhow::anyhow;
use containerd_sandbox::{
    cri::api::v1::LinuxContainerResources,
    data::SandboxData,
    error::{Error, Result},
};
use log::{debug, error};
use nix::{
    fcntl::{open, OFlag},
    libc::{dup2, exit, fcntl, kill, setns, FD_CLOEXEC, F_GETFD, F_SETFD},
    sched::CloneFlags,
    sys::stat::Mode,
};
use time::OffsetDateTime;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::watch::Receiver,
    time::sleep,
};

use crate::NAMESPACE_NET;

pub async fn read_file<P: AsRef<Path>>(filename: P) -> Result<String> {
    let mut file = tokio::fs::File::open(&filename).await?;
    let mut content: String = String::new();
    file.read_to_string(&mut content).await?;
    Ok(content)
}

pub fn get_netns(data: &SandboxData) -> String {
    if !data.netns.is_empty() {
        data.netns.to_string()
    } else if let Some(spec) = &data.spec {
        let mut netns = "".to_string();
        if let Some(l) = &spec.linux {
            for ns in &l.namespaces {
                if ns.r#type == NAMESPACE_NET {
                    netns = ns.path.clone();
                }
            }
        }
        netns
    } else {
        "".to_string()
    }
}

pub fn get_resources(data: &SandboxData) -> Option<&LinuxContainerResources> {
    data.config
        .as_ref()
        .and_then(|c| c.linux.as_ref())
        .and_then(|l| l.resources.as_ref())
}

pub fn get_overhead_resources(data: &SandboxData) -> Option<&LinuxContainerResources> {
    data.config
        .as_ref()
        .and_then(|c| c.linux.as_ref())
        .and_then(|l| l.overhead.as_ref())
}

#[allow(dead_code)]
pub fn get_total_resources(data: &SandboxData) -> Option<LinuxContainerResources> {
    return data
        .config
        .as_ref()
        .and_then(|c| c.linux.as_ref())
        .and_then(|l| {
            l.resources.as_ref()?;
            if l.overhead.is_none() {
                return l.resources.clone();
            }
            Some(merge_resources(
                l.resources.as_ref().unwrap(),
                l.overhead.as_ref().unwrap(),
            ))
        });
}

#[allow(dead_code)]
fn merge_resources(
    resource1: &LinuxContainerResources,
    resource2: &LinuxContainerResources,
) -> LinuxContainerResources {
    // 1. merge oom_score_adj with the larger one
    let oom_score_adj = if resource1.oom_score_adj > resource2.oom_score_adj {
        resource1.oom_score_adj
    } else {
        resource2.oom_score_adj
    };

    // 2. merge hugepage limits, sum the limit for those with same page size
    let mut hugepage_limits = resource1.hugepage_limits.clone();
    for h2 in &resource2.hugepage_limits {
        let found = false;
        for l in &mut hugepage_limits {
            if l.page_size == h2.page_size {
                l.limit += h2.limit;
            }
        }
        if !found {
            hugepage_limits.push(h2.clone())
        }
    }

    // 3. merge unified, not sure how to handle same key, pick only one of them
    let mut unified = resource1.unified.clone();
    for (k, v) in &resource2.unified {
        if !unified.contains_key(k) {
            unified.insert(k.clone(), v.clone());
        }
    }

    // merge cpuset_cpus, if error happend, log and use resource1
    let cpuset_cpus = if let Ok(c) = merge_cpusets(&resource1.cpuset_cpus, &resource2.cpuset_cpus) {
        c
    } else {
        error!(
            "failed to merge cpusets {} with {}",
            resource1.cpuset_cpus, resource2.cpuset_cpus
        );
        resource1.cpuset_cpus.to_string()
    };

    // merge cpuset_mems, if error happend, log and use resource1
    let cpuset_mems = if let Ok(c) = merge_cpusets(&resource1.cpuset_mems, &resource2.cpuset_mems) {
        c
    } else {
        error!(
            "failed to merge cpuset mems {} with {}",
            resource1.cpuset_mems, resource2.cpuset_mems
        );
        resource1.cpuset_mems.to_string()
    };

    LinuxContainerResources {
        cpu_period: resource1.cpu_period,
        cpu_quota: resource1.cpu_quota
            + resource2.cpu_quota * resource1.cpu_period / resource2.cpu_period,
        cpu_shares: resource1.cpu_shares + resource2.cpu_shares,
        memory_limit_in_bytes: resource1.memory_limit_in_bytes + resource2.memory_limit_in_bytes,
        oom_score_adj,
        cpuset_cpus,
        cpuset_mems,
        hugepage_limits,
        unified,
        memory_swap_limit_in_bytes: resource1.memory_swap_limit_in_bytes
            + resource2.memory_swap_limit_in_bytes,
    }
}

#[allow(dead_code)]
fn merge_cpusets(cpusets1: &str, cpusets2: &str) -> Result<String> {
    let cpuset1_parts = cpuset_parts(cpusets1)?;
    let cpuset2_parts = cpuset_parts(cpusets2)?;
    let mut cpuset_parts = vec![];
    for p1 in cpuset1_parts {
        let mut base = p1;
        for (low, high) in &cpuset2_parts {
            base = merge_cpuset(base, (*low, *high));
        }
        cpuset_parts.push(base);
    }
    for (low, high) in &cpuset2_parts {
        let mut intersected = false;
        for (low1, high1) in &cpuset_parts {
            intersected = intersected || cpuset_intersect((*low, *high), (*low1, *high1));
        }
        if !intersected {
            cpuset_parts.push((*low, *high));
        }
    }
    Ok(cpuset_parts
        .into_iter()
        .map(cpuset_tostring)
        .collect::<Vec<String>>()
        .join(","))
}

#[allow(dead_code)]
fn merge_cpuset(base: (u32, u32), delta: (u32, u32)) -> (u32, u32) {
    let (mut low, mut high) = base;
    if delta.1 < low {
        return (low, high);
    }
    if delta.0 > high {
        return (low, high);
    }
    if delta.0 < low {
        low = delta.0
    }
    if delta.1 > high {
        high = delta.1
    }
    (low, high)
}

#[allow(dead_code)]
fn cpuset_intersect(cpuset1: (u32, u32), cpuset2: (u32, u32)) -> bool {
    if cpuset2.1 < cpuset1.0 {
        return false;
    }
    if cpuset2.0 > cpuset1.1 {
        return false;
    }
    true
}

#[allow(dead_code)]
fn cpuset_parts(cpuset: &str) -> Result<Vec<(u32, u32)>> {
    let mut cpuset1_parts = vec![];
    let c1 = cpuset.split(',');
    for ps in c1 {
        cpuset1_parts.push(cpuset_one_part(ps)?);
    }
    Ok(cpuset1_parts)
}

#[allow(dead_code)]
fn cpuset_one_part(cpuset: &str) -> Result<(u32, u32)> {
    let parts = cpuset.split('-').collect::<Vec<&str>>();
    let low = parts[0]
        .trim()
        .parse::<u32>()
        .map_err(|_e| Error::InvalidArgument("cpuset format error".to_string()))?;
    let mut high = low;
    if parts.len() == 2 {
        high = parts[1]
            .trim()
            .parse::<u32>()
            .map_err(|_e| Error::InvalidArgument("cpuset format error".to_string()))?;
    }
    Ok((low, high))
}

#[allow(dead_code)]
pub fn cpuset_tostring(cpuset: (u32, u32)) -> String {
    if cpuset.0 == cpuset.1 {
        return cpuset.0.to_string();
    }
    format!("{}-{}", cpuset.0, cpuset.1)
}

pub async fn get_host_memory_in_mb() -> Result<u64> {
    let mut lines = File::open("/proc/meminfo")
        .await
        .map(|f| BufReader::new(f).lines())?;
    while let Some(line) = lines.next_line().await? {
        let fields = line.split_whitespace().collect::<Vec<&str>>();
        if fields.len() >= 3 && fields.first() == Some(&"MemTotal:") && fields.get(2) == Some(&"kB")
        {
            let mkb = fields
                .get(1)
                .ok_or_else(|| Error::InvalidArgument("/proc/meminfo format error".to_string()))
                .and_then(|x| {
                    x.parse::<u64>().map_err(|e| {
                        anyhow!("failed to parse memory from /proc/memoryinfo, {}", e).into()
                    })
                })?;
            return Ok(mkb / 1024);
        }
    }

    Err(anyhow!("can not get host memory info from /proc/meminfo").into())
}

// wait_pid waits for non-children process exit
// we can only poll using kill(pid, 0) before kernel 5.3
// we may open pidfd and epoll on it to get notification after kernel 5.3
pub async fn wait_pid(pid: i32) -> (u32, i128) {
    loop {
        let kill_result = unsafe { kill(pid, 0) };
        if kill_result != 0 {
            let now = OffsetDateTime::now_utc();
            return (0, now.unix_timestamp_nanos());
        }
        sleep(Duration::from_millis(5)).await;
    }
}

pub async fn write_file_async<P: AsRef<Path>>(path: P, s: &str) -> Result<()> {
    let path = path.as_ref();
    let mut f = OpenOptions::new()
        .write(true)
        .open(path)
        .await
        .map_err(|e| anyhow!("failed to open path {}: {}", path.display(), e))?;
    f.write_all(s.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to write string to path {}: {}", path.display(), e))?;
    f.sync_data()
        .await
        .map_err(|e| anyhow!("failed to sync data to path {}: {}", path.display(), e))?;
    Ok(())
}

pub async fn write_file_atomic<P: AsRef<Path>>(path: P, s: &str) -> Result<()> {
    let path = path.as_ref();
    let file = path
        .file_name()
        .ok_or_else(|| Error::InvalidArgument(String::from("path illegal")))?;
    let tmp_path = path
        .parent()
        .map(|x| x.join(format!(".{}", file.to_str().unwrap_or(""))))
        .ok_or_else(|| Error::InvalidArgument(String::from("failed to create tmp path")))?;
    let tmp_path = tmp_path.to_str().ok_or_else(|| {
        Error::InvalidArgument(format!("failed to get path: {}", tmp_path.display()))
    })?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)
        .await
        .map_err(|e| anyhow!("failed to open path {}, {}", tmp_path, e))?;
    f.write_all(s.as_bytes())
        .await
        .map_err(|e| anyhow!("failed to write string to path {}, {}", tmp_path, e))?;
    f.sync_data()
        .await
        .map_err(|e| anyhow!("failed to sync data to path {}, {}", tmp_path, e))?;

    tokio::fs::rename(tmp_path, path)
        .await
        .map_err(|e| anyhow!("failed to rename file: {}", e).into())
}

pub fn bool_to_on_off(b: &bool) -> String {
    if *b {
        "on".to_string()
    } else {
        "off".to_string()
    }
}

pub fn bool_to_socket_server(b: &bool) -> String {
    if *b {
        "server".to_string()
    } else {
        "".to_string()
    }
}

pub fn bool_to_socket_nowait(b: &bool) -> String {
    if *b {
        "nowait".to_string()
    } else {
        "".to_string()
    }
}

pub fn vec_to_string<T: ToString>(v: &[T]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(":")
}

pub fn fds_to_vectors<T>(fds: &Vec<T>) -> String {
    (2 * fds.len() + 2).to_string()
}

pub async fn wait_channel<T: Copy>(t: Duration, mut rx: Receiver<T>) -> Result<T> {
    let tf = tokio::time::timeout(t, rx.changed());
    tf.await
        .map_err(|e| anyhow!("wait task timeout, {}", e))?
        .map_err(|e| anyhow!("failed to join wait handle, {}", e))?;
    Ok(*rx.borrow())
}

pub async fn read_std<T: AsyncRead + Unpin>(std: T, prefix: &str) -> Result<()> {
    let mut buf_reader = BufReader::new(std);
    loop {
        let mut line = String::new();
        let res = buf_reader.read_line(&mut line).await;
        match res {
            Ok(c) => {
                if c == 0 {
                    return Ok(());
                }
                debug!("{}: {}", prefix, line.trim());
            }
            Err(e) => {
                error!("failed to read {} log {}", prefix, e);
                return Err(e.into());
            }
        }
    }
}

pub fn safe_open_file<P: ?Sized + nix::NixPath>(
    path: &P,
    oflag: OFlag,
    mode: Mode,
) -> std::result::Result<OwnedFd, nix::Error> {
    let fd = open(path, oflag, mode)?;
    // SAFETY: contruct a OwnedFd from RawFd, close fd when OwnedFd drop
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn set_cmd_netns(cmd: &mut Command, netns: &str) -> Result<()> {
    if !netns.is_empty() {
        let netns_fd = safe_open_file(netns, OFlag::O_CLOEXEC, Mode::empty())
            .map_err(|e| anyhow!("failed to open netns {}", e))?;
        unsafe {
            cmd.pre_exec(move || {
                let setns_result = setns(netns_fd.as_raw_fd(), CloneFlags::CLONE_NEWNET.bits());
                if setns_result != 0 {
                    eprintln!("failed to set netns: {}", setns_result);
                    exit(127);
                }
                Ok(())
            })
        };
    }
    Ok(())
}

pub fn set_cmd_fd(cmd: &mut Command, fds: Vec<RawFd>) -> Result<()> {
    unsafe {
        cmd.pre_exec(move || {
            for (i, &fd) in fds.iter().enumerate() {
                let dest_fd = (3 + i) as RawFd;
                let src_fd = fd;

                if src_fd == dest_fd {
                    let flags = fcntl(src_fd, F_GETFD);
                    if flags < 0 || fcntl(src_fd, F_SETFD, flags & !FD_CLOEXEC) < 0 {
                        eprintln!("failed to call fnctl");
                        exit(127);
                    }
                } else if dup2(src_fd, dest_fd) < 0 {
                    eprintln!("failed to call dup2");
                    exit(127);
                }
            }
            Ok(())
        })
    };
    Ok(())
}

pub fn get_sandbox_cgroup_parent_path(data: &SandboxData) -> Option<String> {
    data.config
        .as_ref()
        .and_then(|c| c.linux.as_ref())
        .map(|l| l.cgroup_parent.clone())
}
