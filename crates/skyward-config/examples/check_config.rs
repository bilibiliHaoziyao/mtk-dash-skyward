//! 配置自检：用真实的 DeviceConfig::parse() 跑一遍加载期校验。
//!
//! 用法：
//!   cargo run -p skyward-config --example check_config -- devices/dash.toml
//!
//! 之所以需要它：parse() 除了 TOML 语法，还会校验 [stock] package/version、
//! [haptics] strength、[[service]] 的 user/groups/capabilities 白名单、
//! [wlan] 的 probe/attempts/nodes/mounts/settings/firmware、[[owners]] 等。
//! 肉眼看着对的 TOML 完全可能在这里被拒，而它在真机上表现为
//! bring_up() 提前返回 —— 也就是黑屏。刷机前必须跑一次。

fn main() {
    let path = std::env::args().nth(1).expect("usage: check_config <device.toml>");
    let text = std::fs::read_to_string(&path).expect("read the config");
    match skyward_config::DeviceConfig::parse(&text) {
        Ok(cfg) => {
            let w = cfg.wlan.as_ref().expect("a WLAN is described");
            println!("PARSE OK: {path}");
            println!("  device       : codename={} recovery_partition={} restart_service_directory={}",
                     cfg.device.codename, cfg.device.recovery_partition, cfg.device.restart_service_directory);
            println!("  display      : {}x{} density={} fastest_refresh={}",
                     cfg.display.width, cfg.display.height, cfg.display.density, cfg.display.fastest_refresh);
            println!("  modules      : sources={:?} load={} modules", cfg.modules.sources, cfg.modules.load.len());
            println!("  partitions   : mounted={:?}", cfg.partitions.mounted);
            println!("  services     : {} entries", cfg.services.len());
            println!("  owners       : {} runs", cfg.owners.len());
            println!("  wlan         : {} modules, {} nodes, {} mounts, {} writes, attempts={}",
                     w.modules.len(), w.nodes.len(), w.mounts.len(), w.writes.len(), w.attempts);
            println!("  wlan.settings: {:?}", w.settings.as_ref().map(|s| (&s.property, &s.value)));
            println!("  wlan.service : {} (interface={})", w.service, w.interface);
        }
        Err(e) => {
            eprintln!("PARSE FAIL: {e:#}");
            std::process::exit(1);
        }
    }
}
