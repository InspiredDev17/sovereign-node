//! Process-lifetime leases for daemon singleton and owner-local mutations.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{FlockOperation, Mode, OFlags, fchmod, flock, openat};
use thiserror::Error;

const DAEMON_LOCK: &str = ".daemon.lock";
const ADMIN_LOCK: &str = ".admin.lock";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseKind {
    Daemon,
    AdminMutation,
}

impl LeaseKind {
    const fn filename(self) -> &'static str {
        match self {
            Self::Daemon => DAEMON_LOCK,
            Self::AdminMutation => ADMIN_LOCK,
        }
    }
}

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("lifecycle lease requires Unix filesystem locking")]
    UnsupportedPlatform,
    #[error("lifecycle path is invalid: {0}")]
    InvalidPath(&'static str),
    #[error("another {0} operation is active")]
    Busy(&'static str),
    #[error("lifecycle filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
}

/// The open descriptor owns the advisory lock. Dropping the lease releases it.
#[derive(Clone, Debug)]
pub struct LifecycleLease {
    _file: Arc<File>,
    path: PathBuf,
    kind: LeaseKind,
}

impl LifecycleLease {
    pub fn acquire(data_dir: &Path, kind: LeaseKind) -> Result<Self, LifecycleError> {
        if !cfg!(unix) {
            return Err(LifecycleError::UnsupportedPlatform);
        }
        let metadata = fs::symlink_metadata(data_dir)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LifecycleError::InvalidPath(
                "data directory must be a real directory",
            ));
        }

        let directory = openat(
            rustix::fs::CWD,
            data_dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno_to_lifecycle)?;
        let directory = File::from(directory);
        let directory_metadata = directory.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            if directory_metadata.uid() != rustix::process::geteuid().as_raw()
                || directory_metadata.permissions().mode() & 0o077 != 0
            {
                return Err(LifecycleError::InvalidPath(
                    "data directory must be owner-only and owned by this account",
                ));
            }
        }
        let descriptor = openat(
            &directory,
            kind.filename(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(errno_to_lifecycle)?;
        let file = File::from(descriptor);
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if matches!(error.raw_os_error(), 11 | 35) {
                LifecycleError::Busy(match kind {
                    LeaseKind::Daemon => "daemon",
                    LeaseKind::AdminMutation => "owner-local mutation",
                })
            } else {
                errno_to_lifecycle(error)
            }
        })?;

        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(LifecycleError::InvalidPath("lock must be a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.nlink() != 1 {
                return Err(LifecycleError::InvalidPath(
                    "lock must be singly linked and owned by this account",
                ));
            }
            fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(errno_to_lifecycle)?;
        }

        Ok(Self {
            _file: Arc::new(file),
            path: data_dir.join(kind.filename()),
            kind,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn kind(&self) -> LeaseKind {
        self.kind
    }
}

fn errno_to_lifecycle(error: rustix::io::Errno) -> LifecycleError {
    LifecycleError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn same_lease_is_exclusive_and_different_kinds_can_coexist() -> Result<(), LifecycleError> {
        let directory = TempDir::new()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        }
        let daemon = LifecycleLease::acquire(directory.path(), LeaseKind::Daemon)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                daemon.path().metadata()?.permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(matches!(
            LifecycleLease::acquire(directory.path(), LeaseKind::Daemon),
            Err(LifecycleError::Busy("daemon"))
        ));
        let admin = LifecycleLease::acquire(directory.path(), LeaseKind::AdminMutation)?;
        assert_eq!(daemon.kind(), LeaseKind::Daemon);
        assert_eq!(admin.kind(), LeaseKind::AdminMutation);
        let task_lease = daemon.clone();
        drop(daemon);
        assert!(matches!(
            LifecycleLease::acquire(directory.path(), LeaseKind::Daemon),
            Err(LifecycleError::Busy("daemon"))
        ));
        drop(task_lease);
        LifecycleLease::acquire(directory.path(), LeaseKind::Daemon)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_symlink_is_rejected() -> Result<(), LifecycleError> {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new()?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let target = directory.path().join("target");
        File::create(&target)?;
        symlink(&target, directory.path().join(DAEMON_LOCK))?;
        assert!(LifecycleLease::acquire(directory.path(), LeaseKind::Daemon).is_err());
        Ok(())
    }
}
