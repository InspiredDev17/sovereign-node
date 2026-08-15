use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use rustix::fs::{Mode, OFlags};
use thiserror::Error;

const MAX_PRIVATE_FILE_BYTES: u64 = 64 * 1_024 * 1_024;

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
    #[error("security-sensitive path is not a regular singly-linked file: {0}")]
    Type(String),
    #[error("security-sensitive file exceeds its bounded size: {0}")]
    Size(String),
    #[error("security-sensitive ancestor is replaceable or invalid: {0}")]
    Ancestor(String),
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
        let resolved = fs::canonicalize(path)?;
        validate_sensitive_ancestors(&resolved, true)?;
    }

    Ok(())
}

pub fn read_private_file(path: &Path) -> Result<Vec<u8>, SecureFileError> {
    read_secure_file(path, MAX_PRIVATE_FILE_BYTES, true, false)
}

pub fn read_private_file_bounded(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SecureFileError> {
    read_secure_file(path, maximum_bytes, true, false)
}

/// Read integrity-critical configuration from one validated descriptor. Root
/// ownership and the dedicated service account are both supported; group or
/// world write permission is never accepted.
pub fn read_configuration_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Vec<u8>, SecureFileError> {
    read_secure_file(path, maximum_bytes, false, true)
}

fn read_secure_file(
    path: &Path,
    maximum_bytes: u64,
    require_private_mode: bool,
    allow_root_owner: bool,
) -> Result<Vec<u8>, SecureFileError> {
    if maximum_bytes == 0 {
        return Err(SecureFileError::Size(path.display().to_string()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| SecureFileError::Ancestor(path.display().to_string()))?;
    let name = path
        .file_name()
        .ok_or_else(|| SecureFileError::Type(path.display().to_string()))?;
    let resolved_parent = fs::canonicalize(parent)?;
    validate_sensitive_ancestors(&resolved_parent, true)?;
    let resolved_path = resolved_parent.join(name);
    let descriptor = rustix::fs::open(
        &resolved_path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = fs::File::from(descriptor);
    let metadata = file.metadata()?;
    validate_open_file_metadata(
        &resolved_path,
        &metadata,
        maximum_bytes,
        require_private_mode,
        allow_root_owner,
    )?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| SecureFileError::Size(resolved_path.display().to_string()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(SecureFileError::Size(resolved_path.display().to_string()));
    }
    Ok(bytes)
}

fn validate_open_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    maximum_bytes: u64,
    require_private_mode: bool,
    allow_root_owner: bool,
) -> Result<(), SecureFileError> {
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(if metadata.len() > maximum_bytes {
            SecureFileError::Size(path.display().to_string())
        } else {
            SecureFileError::Type(path.display().to_string())
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode_mask = if require_private_mode { 0o077 } else { 0o022 };
        if metadata.mode() & mode_mask != 0 {
            return Err(SecureFileError::Permissions(path.display().to_string()));
        }
        let owner = metadata.uid();
        let expected = rustix::process::geteuid().as_raw();
        if owner != expected && !(allow_root_owner && owner == 0) {
            return Err(SecureFileError::Ownership(path.display().to_string()));
        }
        if metadata.nlink() != 1 {
            return Err(SecureFileError::Type(path.display().to_string()));
        }
    }
    Ok(())
}

pub(crate) fn validate_sensitive_ancestors(
    resolved_parent: &Path,
    allow_root_owner: bool,
) -> Result<(), SecureFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let expected = rustix::process::geteuid().as_raw();
        let mut current = Some(resolved_parent);
        while let Some(path) = current {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.mode() & 0o022 != 0
                || (metadata.uid() != expected && !(allow_root_owner && metadata.uid() == 0))
            {
                return Err(SecureFileError::Ancestor(path.display().to_string()));
            }
            current = path.parent();
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn descriptor_reader_rejects_links_modes_types_and_oversize() -> Result<(), SecureFileError> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = TempDir::new()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let valid = directory.path().join("valid");
        create_private_file(&valid, b"secret")?;
        assert_eq!(read_private_file_bounded(&valid, 6)?, b"secret");
        assert!(matches!(
            read_private_file_bounded(&valid, 5),
            Err(SecureFileError::Size(_))
        ));

        let linked = directory.path().join("linked");
        symlink(&valid, &linked)?;
        assert!(read_private_file(&linked).is_err());

        let shared = directory.path().join("shared");
        fs::write(&shared, b"value")?;
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o666))?;
        assert!(matches!(
            read_configuration_file(&shared, 100),
            Err(SecureFileError::Permissions(_))
        ));
        assert!(read_private_file(directory.path()).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn configuration_reader_accepts_service_owned_readable_integrity_file()
    -> Result<(), SecureFileError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("node.toml");
        fs::write(&path, b"policy_version = 1\n")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert_eq!(
            read_configuration_file(&path, 1024)?,
            b"policy_version = 1\n"
        );
        Ok(())
    }
}
