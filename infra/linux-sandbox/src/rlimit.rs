use std::io;

use af_sandbox::ResourceLimits;

type Resource = libc::__rlimit_resource_t;

#[derive(Debug, Clone)]
pub(crate) struct RlimitPlan {
    entries: Vec<(Resource, libc::rlimit)>,
}

impl RlimitPlan {
    pub(crate) fn from_limits(limits: &ResourceLimits) -> io::Result<Self> {
        let mut entries = Vec::new();
        if let Some(value) = limits.max_memory_bytes {
            entries.push((libc::RLIMIT_AS, limit_from(value)?));
        }
        // Do not map max_processes to RLIMIT_NPROC.
        //
        // RLIMIT_NPROC is per-real-UID, not per-sandbox process tree. Applying it
        // here can cause namespace creation to fail (`EAGAIN`) when the user has
        // many other processes outside the sandbox. Process-count limits are
        // enforced by cgroup `pids.max` when cgroup governance is available.
        if let Some(value) = limits.max_file_size_bytes {
            entries.push((libc::RLIMIT_FSIZE, limit_from(value)?));
        }
        if let Some(value) = limits.cpu_time_limit_seconds {
            entries.push((libc::RLIMIT_CPU, limit_from(value)?));
        }
        Ok(Self { entries })
    }

    pub(crate) fn apply(&self) -> io::Result<()> {
        for (resource, limit) in &self.entries {
            let rc = unsafe { libc::setrlimit(*resource, limit as *const libc::rlimit) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

fn limit_from(value: u64) -> io::Result<libc::rlimit> {
    let converted = libc::rlim_t::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "resource limit `{value}` exceeds platform rlimit max {}",
                libc::rlim_t::MAX
            ),
        )
    })?;
    Ok(libc::rlimit {
        rlim_cur: converted,
        rlim_max: converted,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn ignores_max_processes_for_rlimit_plan() {
        let plan = RlimitPlan::from_limits(&ResourceLimits {
            elapsed_timeout: Duration::from_secs(10),
            cpu_time_limit_seconds: Some(2),
            max_memory_bytes: Some(32 * 1024 * 1024),
            max_processes: Some(16),
            max_file_size_bytes: Some(1024),
            cpu_max_percent: None,
        })
        .expect("rlimit plan should build");

        assert_eq!(plan.entries.len(), 3);
        assert!(
            plan.entries
                .iter()
                .all(|(resource, _)| *resource != libc::RLIMIT_NPROC)
        );
    }
}
