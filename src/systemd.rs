use std::env;
use std::os::fd::RawFd;
use std::collections::HashMap;

pub fn listen_fds_named() -> HashMap<String, RawFd> {
    let pid_ok = env::var("LISTEN_PID")
        .map(|v| v == std::process::id().to_string())
        .unwrap_or(false);
    if !pid_ok {
        return HashMap::new();
    }

    let n_fds = env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);

    let names = env::var("LISTEN_FDNAMES").unwrap_or_default();
    let names: Vec<String> = names.split(':').map(|s| s.to_owned()).collect(); // FDNAMES are colon-separated

    let mut map = HashMap::new();
    for i in 0..n_fds {
        let fd = 3 + i;
        let default = format!("fd{}", fd);
        let name = names.get(i as usize).unwrap_or(&default);
        map.insert(name.clone(), fd);
    }
    map
}
