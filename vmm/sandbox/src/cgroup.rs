use std::path::{Path, PathBuf};

use anyhow::{anyhow, Ok, Result};
use cgroups_rs::{
    cgroup_builder::*, cpu::CpuController, cpuset::CpuSetController, hugetlb::HugeTlbController,
    memory::MemController, Cgroup, Hierarchy, Subsystem,
};
use containerd_sandbox::{cri::api::v1::LinuxContainerResources, data::SandboxData};

use crate::{
    utils::{
        get_overhead_resources, get_resources, get_sandbox_cgroup_parent_path, get_total_resources,
    },
    vm::VcpuThreads,
};

pub const VCPU_CGROUP_NAME: &str = "vcpu";
pub const POD_OVERHEAD_CGROUP_NAME: &str = "pod_overhead";

/// `SandboxCgroup` represents a set of cgroups for a sandbox.
#[derive(Default, Debug)]
pub struct SandboxCgroup {
    pub sandbox_cgroup: Cgroup,
    pub vcpu_cgroup: Cgroup,
    pub pod_overhead_cgroup: Cgroup,
}

impl SandboxCgroup {
    pub fn create_sandbox_cgroups(sandbox_data: &SandboxData) -> Result<Self> {
        let sandbox_cgroup_parent_path = get_sandbox_cgroup_parent_path(sandbox_data)
            .ok_or(anyhow!("failed to get sandbox cgroup parent path"))?;
        let all_hiers = cgroups_rs::hierarchies::auto();

        // Create sandbox cgroup in the all cgroup subsystem dir
        let sandbox_cgroup_path_str = format!("{}/{}", sandbox_cgroup_parent_path, sandbox_data.id);
        let mut sandbox_cgroup_path = Path::new(sandbox_cgroup_path_str.as_str());
        // CgroupBuilder::new() func doesn't accept the cgroup name has "/" prefix,
        // So need to remove the "/" prefix for sandbox_cgroup_path
        if sandbox_cgroup_path.has_root() {
            sandbox_cgroup_path = sandbox_cgroup_path.strip_prefix("/")?;
        }

        let sandbox_cgroup =
            CgroupBuilder::new(sandbox_cgroup_path.to_str().unwrap()).build(all_hiers)?;

        // Only create the vcpu and pod_overhead cgroups in the cpu cgroup subsystem
        let vcpu_cgroup_path = format!(
            "{}/{}",
            sandbox_cgroup_path.to_str().unwrap(),
            VCPU_CGROUP_NAME
        );
        let vcpu_cgroup =
            CgroupBuilder::new(vcpu_cgroup_path.as_str()).build(cpu_subsystem_hier())?;

        let pod_overhead_cgroup_path = format!(
            "{}/{}",
            sandbox_cgroup_path.to_str().unwrap(),
            POD_OVERHEAD_CGROUP_NAME
        );
        let pod_overhead_cgroup =
            CgroupBuilder::new(pod_overhead_cgroup_path.as_str()).build(cpu_subsystem_hier())?;

        Ok(SandboxCgroup {
            sandbox_cgroup,
            vcpu_cgroup,
            pod_overhead_cgroup,
        })
    }

    pub fn update_res_for_sandbox_cgroups(&self, sandbox_data: &SandboxData) -> Result<()> {
        // apply the total resources = sum(sum(containers_resources) + pod_overhead)) in the sandbox cgroup dir
        if let Some(total_resources) = get_total_resources(sandbox_data) {
            apply_cpu_resource(&self.sandbox_cgroup, &total_resources)?;
            apply_memory_resource(&self.sandbox_cgroup, &total_resources)?;
            apply_cpuset_resources(&self.sandbox_cgroup, &total_resources)?;
            apply_hugetlb_resources(&self.sandbox_cgroup, &total_resources)?;
        }

        // apply the cpu resource of containers in the vcpu cpu subsystem cgroup
        if let Some(containers_resources) = get_resources(sandbox_data) {
            apply_cpu_resource(&self.vcpu_cgroup, containers_resources)?;
        }

        // apply the cpu resource of pod_overhead in the pod_overhead cpu subsystem cgroup
        if let Some(overhead_resources) = get_overhead_resources(sandbox_data) {
            apply_cpu_resource(&self.pod_overhead_cgroup, overhead_resources)?;
        }

        Ok(())
    }

    pub fn add_process_into_sandbox_cgroups(
        &self,
        pid: u32,
        vcpu_threads: VcpuThreads,
    ) -> Result<()> {
        // Add vmm process into the sandbox_cgroup
        self.sandbox_cgroup.add_task_by_tgid((pid as u64).into())?;

        // Move vmm process from parent sandbox cgroup into pod_overhead cgroup
        // Then move the all vcpu threads of vmm process into vcpu cgroup
        self.pod_overhead_cgroup
            .add_task_by_tgid((pid as u64).into())?;
        for (_, vcpu_thread_tid) in vcpu_threads.vcpus {
            self.vcpu_cgroup.add_task((vcpu_thread_tid as u64).into())?;
        }

        Ok(())
    }

    pub fn remove_sandbox_cgroups(&self) -> Result<()> {
        remove_sandbox_cgroup(&self.vcpu_cgroup)?;
        remove_sandbox_cgroup(&self.pod_overhead_cgroup)?;
        remove_sandbox_cgroup(&self.sandbox_cgroup)?;
        Ok(())
    }
}

// cgroups-rs crate doesn't provides independent cgroup subsystem hierarchy,
// So we need to implement the Hierarchy trait for spcified cpu cgroup subsystem
#[derive(Debug)]
struct CpuSubsystem {
    cpu_cgroup_root: PathBuf,
}

impl CpuSubsystem {
    pub fn new() -> Self {
        let path = cgroups_rs::hierarchies::V1::new()
            .get_mount_point(cgroups_rs::Controllers::Cpu)
            .unwrap();
        CpuSubsystem {
            cpu_cgroup_root: path,
        }
    }
}

pub fn cpu_subsystem_hier() -> Box<dyn Hierarchy> {
    Box::new(CpuSubsystem::new())
}

impl Hierarchy for CpuSubsystem {
    fn subsystems(&self) -> Vec<cgroups_rs::Subsystem> {
        vec![Subsystem::Cpu(CpuController::new(
            self.cpu_cgroup_root.clone(),
            false,
        ))]
    }

    fn root(&self) -> std::path::PathBuf {
        self.cpu_cgroup_root.parent().unwrap().to_path_buf()
    }

    fn root_control_group(&self) -> Cgroup {
        Cgroup::load(cpu_subsystem_hier(), "")
    }

    fn parent_control_group(&self, path: &str) -> Cgroup {
        let path = Path::new(path);
        let parent_path = path.parent().unwrap().to_string_lossy().to_string();
        Cgroup::load(cpu_subsystem_hier(), parent_path)
    }

    fn v2(&self) -> bool {
        false
    }
}

fn apply_cpu_resource(cgroup: &Cgroup, res: &LinuxContainerResources) -> Result<()> {
    let cpu_controller: &CpuController = cgroup
        .controller_of()
        .ok_or(anyhow!("No cpu controller attached!"))?;
    cpu_controller.set_cfs_period(res.cpu_period.try_into()?)?;
    cpu_controller.set_cfs_quota(res.cpu_quota)?;
    cpu_controller.set_shares(res.cpu_shares.try_into()?)?;
    Ok(())
}

fn apply_memory_resource(cgroup: &Cgroup, res: &LinuxContainerResources) -> Result<()> {
    let mem_controller: &MemController = cgroup
        .controller_of()
        .ok_or(anyhow!("No memory controller attached!"))?;
    mem_controller.set_limit(res.memory_limit_in_bytes)?;
    mem_controller.set_memswap_limit(res.memory_swap_limit_in_bytes)?;
    Ok(())
}

fn apply_cpuset_resources(cgroup: &Cgroup, res: &LinuxContainerResources) -> Result<()> {
    let cpuset_controller: &CpuSetController = cgroup
        .controller_of()
        .ok_or(anyhow!("No cpuset controller attached!"))?;
    cpuset_controller.set_cpus(&res.cpuset_cpus)?;
    cpuset_controller.set_mems(&res.cpuset_mems)?;
    Ok(())
}

fn apply_hugetlb_resources(cgroup: &Cgroup, res: &LinuxContainerResources) -> Result<()> {
    let hugetlb_controller: &HugeTlbController = cgroup
        .controller_of()
        .ok_or(anyhow!("No hugetlb controller attached!"))?;
    for h in res.hugepage_limits.iter() {
        hugetlb_controller.set_limit_in_bytes(h.page_size.as_str(), h.limit)?;
    }
    Ok(())
}

fn remove_sandbox_cgroup(cgroup: &Cgroup) -> Result<()> {
    // get the tids in the current cgroup and then move the tids to parent cgroup
    let tids = cgroup.tasks();
    for tid in tids {
        cgroup.move_task_to_parent(tid)?;
    }

    cgroup.delete()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, result::Result::Ok};

    use cgroups_rs::Controller;
    use containerd_sandbox::{
        cri::api::v1::{HugepageLimit, LinuxPodSandboxConfig},
        PodSandboxConfig,
    };

    use super::*;

    fn create_mock_pod_sandbox_config() -> PodSandboxConfig {
        let mut pod_sandbox_config = PodSandboxConfig::default();
        pod_sandbox_config.linux = Some(LinuxPodSandboxConfig {
            cgroup_parent: "/kubepods/burstable/podxxx".to_string(),
            security_context: None,
            sysctls: HashMap::new(),
            overhead: Some(LinuxContainerResources {
                cpu_period: 100000,
                cpu_quota: 50000,
                cpu_shares: 1024,
                memory_limit_in_bytes: 100 * 1024 * 1024,
                oom_score_adj: 0,
                cpuset_cpus: "".to_string(),
                cpuset_mems: "".to_string(),
                hugepage_limits: vec![],
                unified: HashMap::new(),
                memory_swap_limit_in_bytes: 0 + 100 * 1024 * 1024,
            }),
            resources: Some(LinuxContainerResources {
                cpu_period: 100000,
                cpu_quota: 200000,
                cpu_shares: 1024,
                memory_limit_in_bytes: 1024 * 1024 * 1024,
                oom_score_adj: 0,
                cpuset_cpus: "0-1".to_string(),
                cpuset_mems: "0".to_string(),
                hugepage_limits: vec![HugepageLimit {
                    page_size: "2MB".to_string(),
                    limit: 2 * 1024 * 1024 * 1024,
                }],
                unified: HashMap::new(),
                memory_swap_limit_in_bytes: 0 + 1024 * 1024 * 1024,
            }),
        });
        pod_sandbox_config
    }

    #[test]
    fn test_create_sandbox_cgroups() {
        // Currently only support cgroup V1, cgroup V2 is not supported now
        if cgroups_rs::hierarchies::is_cgroup2_unified_mode() {
            return;
        }

        // Create a SandboxData instance
        let mut sandbox_data = SandboxData::default();
        sandbox_data.id = String::from("test_sandbox");

        // Case 1: sandbox.config is None, expect return the error
        sandbox_data.config = None;
        let result = SandboxCgroup::create_sandbox_cgroups(&sandbox_data);
        match result {
            Ok(_) => panic!("Expected an error, but got Ok"),
            Err(e) => assert_eq!(e.to_string(), "failed to get sandbox cgroup parent path"),
        }

        // Case 2: sandbox.config is corrent, expect create sandbox cgroup successfully
        let pod_sandbox_config = create_mock_pod_sandbox_config();
        sandbox_data.config = Some(pod_sandbox_config);
        let result = SandboxCgroup::create_sandbox_cgroups(&sandbox_data);
        match result {
            Ok(sandbox_cgoups) => {
                // Get the test environment cpu subsystem cgroup mountpoint path
                let cpu_cgroup_root_pathbuf = cgroups_rs::hierarchies::V1::new()
                    .get_mount_point(cgroups_rs::Controllers::Cpu)
                    .unwrap();
                println!("cpu_cgroup_root_pathbuf: {:?}", cpu_cgroup_root_pathbuf);

                // check sandbox level cgroup
                let sandbox_cgroup_cpu_controller: &CpuController =
                    sandbox_cgoups.sandbox_cgroup.controller_of().unwrap();
                assert!(sandbox_cgroup_cpu_controller.path().exists());
                assert_eq!(
                    sandbox_cgroup_cpu_controller.path(),
                    cpu_cgroup_root_pathbuf
                        .join("kubepods/burstable/podxxx/test_sandbox")
                        .as_path()
                );

                // check vcpu level cgroup
                let vcpu_cgroup_cpu_controller: &CpuController =
                    sandbox_cgoups.vcpu_cgroup.controller_of().unwrap();
                assert!(vcpu_cgroup_cpu_controller.path().exists());
                assert_eq!(
                    vcpu_cgroup_cpu_controller.path(),
                    cpu_cgroup_root_pathbuf
                        .join("kubepods/burstable/podxxx/test_sandbox/vcpu")
                        .as_path()
                );
            }
            Err(e) => panic!("Expected an Ok, but got error: {}", e.to_string()),
        }

        // Case 3: If sandbox cgroups already exist in the system, then call create_sandbox_cgroups
        //         function again will not fail
        let result = SandboxCgroup::create_sandbox_cgroups(&sandbox_data);
        match result {
            Ok(sandbox_cgoups) => {
                let sandbox_cgroup_mem_controller: &MemController =
                    sandbox_cgoups.sandbox_cgroup.controller_of().unwrap();
                assert!(sandbox_cgroup_mem_controller.path().exists());
                assert_eq!(
                    sandbox_cgroup_mem_controller.path().to_str().unwrap(),
                    "/sys/fs/cgroup/memory/kubepods/burstable/podxxx/test_sandbox"
                );

                // Clean the test sandbox cgroups
                assert_eq!(sandbox_cgoups.remove_sandbox_cgroups().is_ok(), true);
            }
            Err(e) => panic!("Expected an Ok, but got error: {}", e.to_string()),
        }
    }

    #[test]
    fn test_update_res_for_sandbox_cgroups_success() {
        // Currently only support cgroup V1, cgroup V2 is not supported now
        if cgroups_rs::hierarchies::is_cgroup2_unified_mode() {
            return;
        }

        // Case 1: successfully case
        // Create a SandboxData instance
        let mut sandbox_data = SandboxData::default();
        sandbox_data.id = String::from("test_sandbox");
        sandbox_data.config = Some(create_mock_pod_sandbox_config());

        // Create a SandboxData instance
        let sandbox_cgroups = SandboxCgroup::create_sandbox_cgroups(&sandbox_data).unwrap();
        let result = sandbox_cgroups.update_res_for_sandbox_cgroups(&sandbox_data);

        match result {
            Ok(_) => {
                // Check sandbox level cgroup total resources
                // Check cpu subsystem cgroup limit
                let sandbox_cgroup_cpu_controller: &CpuController =
                    sandbox_cgroups.sandbox_cgroup.controller_of().unwrap();
                assert_eq!(sandbox_cgroup_cpu_controller.cfs_period().unwrap(), 100000);
                assert_eq!(sandbox_cgroup_cpu_controller.cfs_quota().unwrap(), 250000);
                assert_eq!(sandbox_cgroup_cpu_controller.shares().unwrap(), 2048);

                // Check memory subsystem cgroup limit
                let sandbox_cgroup_mem_controller: &MemController =
                    sandbox_cgroups.sandbox_cgroup.controller_of().unwrap();
                let memory_stats = sandbox_cgroup_mem_controller.memory_stat();
                let memory_swap_stats = sandbox_cgroup_mem_controller.memswap();
                assert_eq!(memory_stats.limit_in_bytes, 1124 * 1024 * 1024);
                assert_eq!(memory_swap_stats.limit_in_bytes, 1124 * 1024 * 1024);

                // Check cpuset subsystem cgroup limit
                let sandbox_cgroup_cpuset_controller: &CpuSetController =
                    sandbox_cgroups.sandbox_cgroup.controller_of().unwrap();
                let cpuset_stats = sandbox_cgroup_cpuset_controller.cpuset();
                assert_eq!(cpuset_stats.cpus, vec![(0, 1)]);
                assert_eq!(cpuset_stats.mems, vec![(0, 0)]);

                // Check hugetlb subsystem cgroup limit
                let sandbox_cgroup_hugetlb_controller: &HugeTlbController =
                    sandbox_cgroups.sandbox_cgroup.controller_of().unwrap();
                assert_eq!(
                    sandbox_cgroup_hugetlb_controller
                        .get_sizes()
                        .contains(&"2MB".to_string()),
                    true
                );
                assert_eq!(
                    sandbox_cgroup_hugetlb_controller
                        .limit_in_bytes("2MB")
                        .unwrap(),
                    2 * 1024 * 1024 * 1024
                );

                // check vcpu level cgroup
                let vcpu_cgroup_cpu_controller: &CpuController =
                    sandbox_cgroups.vcpu_cgroup.controller_of().unwrap();
                assert_eq!(vcpu_cgroup_cpu_controller.cfs_period().unwrap(), 100000);
                assert_eq!(vcpu_cgroup_cpu_controller.cfs_quota().unwrap(), 200000);
                assert_eq!(vcpu_cgroup_cpu_controller.shares().unwrap(), 1024);

                // check pod_overhead level cgroup
                let pod_overhead_cgroup_cpu_controller: &CpuController =
                    sandbox_cgroups.pod_overhead_cgroup.controller_of().unwrap();
                assert_eq!(
                    pod_overhead_cgroup_cpu_controller.cfs_period().unwrap(),
                    100000
                );
                assert_eq!(
                    pod_overhead_cgroup_cpu_controller.cfs_quota().unwrap(),
                    50000
                );
                assert_eq!(pod_overhead_cgroup_cpu_controller.shares().unwrap(), 1024);
            }
            Err(e) => panic!("Expected an Ok, but got error: {}", e.to_string()),
        }

        assert_eq!(sandbox_cgroups.remove_sandbox_cgroups().is_ok(), true);
    }
}
