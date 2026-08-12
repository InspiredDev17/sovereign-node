use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecureFileError {
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("security-sensitive path is a symbolic link: {0}")]
    Symlink(String),
    #[error("security-sensitive path has permissions accessible by another user: {0}")]
    Permissions(String),
    #[error("security-sensitive path is owned by a different user: {0}")]
    Ownership(String),
}

pub fn ensure_private_directory(path: &Path) -> Result<(), SecureFileError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(SecureFileError::Symlink(path.display().to_string()));
        }
        if !metadata.is_dir() {
            return Err(SecureFileError::Permissions(path.display().to_string()));
        }
    } else {
        fs::create_dir_all(path)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.mode() & 0o077 != 0 {
            return Err(SecureFileError::Permissions(path.display().to_string()));
        }
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(SecureFileError::Ownership(path.display().to_string()));
        }
    }

    Ok(())
}

pub fn read_private_file(path: &Path) -> Result<Vec<u8>, SecureFileError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(SecureFileError::Symlink(path.display().to_string()));
    }
    if !metadata.is_file() {
        return Err(SecureFileError::Permissions(path.display().to_string()));
    }
    validate_private_metadata(path, &metadata)?;
    Ok(fs::read(path)?)
}

pub fn create_private_file(path: &Path, contents: &[u8]) -> Result<(), SecureFileError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    validate_private_metadata(path, &file.metadata()?)?;
    Ok(())
}

fn validate_private_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), SecureFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.mode() & 0o077 != 0 {
            return Err(SecureFileError::Permissions(path.display().to_string()));
        }
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(SecureFileError::Ownership(path.display().to_string()));
        }
    }
    Ok(())
}

#[must_use]
pub fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// v0.1 only serves remote actions on Unix, where owner and mode checks are enforced.
#[must_use]
pub const fn platform_security_supported() -> bool {
    cfg!(unix)
}
