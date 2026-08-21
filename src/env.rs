//! The one platform fact this crate still needs to read for itself: is this
//! a WSL2 guest? `locate.rs`'s own Windows-exe lookup needs this directly,
//! independent of resolving Core's address — everything *that* needs
//! (gateway detection, the actual probe) now lives inside
//! `embarch_topology::software::resolve_software_topology` (design.md §3
//! decisions 2, 3), so this file shrank to just this.

/// Is this a WSL2 guest?
pub fn under_wsl2() -> bool {
    let proc_version = std::fs::read_to_string("/proc/version").ok();
    let wsl_distro = std::env::var("WSL_DISTRO_NAME").ok();
    embarch_topology::software::detect_wsl2(proc_version.as_deref(), wsl_distro.as_deref())
}
