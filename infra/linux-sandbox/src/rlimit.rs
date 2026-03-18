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
        if let Some(value) = limits.max_processes {
            entries.push((libc::RLIMIT_NPROC, limit_from(value)?));
        }
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
