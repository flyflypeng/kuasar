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

use std::path::Path;

use anyhow::anyhow;
use containerd_sandbox::error;
use serde::de::DeserializeOwned;
use serde_derive::Deserialize;
use tokio::fs::read_to_string;

use crate::sandbox::SandboxConfig;

#[derive(Deserialize, Debug)]
pub struct Config<T> {
    pub sandbox: SandboxConfig,
    pub hypervisor: T,
}

impl<T: DeserializeOwned> Config<T> {
    pub async fn parse<P: AsRef<Path>>(path: P) -> error::Result<Self> {
        let toml_str = read_to_string(&path).await?;
        let conf: Self = toml::from_str(&toml_str)
            .map_err(|e| anyhow!("failed to parse kuasar sandboxer config {}", e))?;
        Ok(conf)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::stratovirt::config::{PcieRootPorts, StratoVirtVMConfig};
    use std::fs::{remove_file, File};
    use std::io::{BufRead, BufReader, BufWriter, Write};
    use std::path::{Path, PathBuf};

    #[tokio::test]
    async fn test_parse_strato_virt_vmconfig() {
        let mut config_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        config_path_buf.push("config_stratovirt.toml");
        let config_path = Path::new(&config_path_buf);

        let config: Config<StratoVirtVMConfig> = Config::parse(config_path).await.unwrap();
        println!("get stratovirt config: {:?}", config);

        let mut vmconfig = StratoVirtVMConfig::default();
        vmconfig.path = "/usr/bin/stratovirt".to_string();
        vmconfig.machine_type = "virt,mem-share=on".to_string();
        vmconfig.block_device_driver = "virtio-blk".to_string();
        vmconfig.pcie_root_ports = PcieRootPorts(15);
        vmconfig.common.kernel_path = "/var/lib/kuasar/vmlinux.bin".to_string();
        vmconfig.common.initrd_path = "/var/lib/kuasar/kuasar.initrd".to_string();
        vmconfig.common.image_path = "".to_string();
        vmconfig.common.kernel_params =
            "task.log_level=debug task.sharefs_type=virtiofs".to_string();
        vmconfig.common.vcpus = 1;
        vmconfig.common.memory_in_mb = 1024;
        vmconfig.common.debug = true;

        vmconfig.virtiofsd_conf.path = "/usr/bin/vhost_user_fs".to_string();

        assert_eq!(vmconfig, config.hypervisor);
    }

    #[tokio::test]
    async fn test_parse_default_pcie_root_ports_config() {
        let mut config_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        config_path_buf.push("config_stratovirt.toml");
        let config_path = Path::new(&config_path_buf);

        let mut config_test_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        config_test_path_buf.push("config_stratovirt_test.toml");
        let config_test_path = Path::new(&config_test_path_buf);

        let mut config_file = File::open(config_path).unwrap();
        let mut config_test_file = File::create(config_test_path).unwrap();

        // read the line by line from config_stratovirt.toml file
        // and write it into temporary config_stratovirt_test.toml
        // and comment the pcie_root_ports field
        let readers = BufReader::new(config_file);
        let mut writter = BufWriter::new(config_test_file);

        for line in readers.lines() {
            if let Ok(content) = line {
                if content.contains("pcie_root_ports") {
                    writter.write_fmt(format_args!("#{}\n", content)).unwrap();
                } else {
                    writter.write_fmt(format_args!("{}\n", content)).unwrap();
                }
            }
        }

        writter.flush().unwrap();

        // parse the temporary config_stratovirt_test.toml file
        let config_test: Config<StratoVirtVMConfig> =
            Config::parse(config_test_path).await.unwrap();
        println!("get test stratovirt config: {:?}", config_test);

        // clean the temporary file
        remove_file(config_test_path).unwrap();

        assert_eq!(15, config_test.hypervisor.pcie_root_ports.0);
    }
}
