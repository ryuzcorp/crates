//! Small filesystem helpers the runner needs but the standard library does
//! not spell out.
//!
//! The two jobs here are security-relevant, because the paths and contents
//! come from a checkout an untrusted step controlled.

use std::path::{Path, PathBuf};

/// Recursively `lchown` every entry under `path` without following symlinks.
///
/// The artifact copy comes out of a container that untrusted steps controlled,
/// so a step could leave a symlink pointing at a platform path; traversing it
/// would hand that path to a chown. Returns false if any entry failed (the
/// caller logs and continues: ownership is best-effort, the copy already
/// happened and the worktree is only ever read by the deploy).
#[cfg(unix)]
pub(crate) fn lchown_tree(path: &Path, uid: u32, gid: u32) -> bool {
    let mut ok = true;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            ok = false;
            continue;
        };
        if std::os::unix::fs::lchown(&p, Some(uid), Some(gid)).is_err() {
            ok = false;
        }
        if meta.file_type().is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                for entry in rd.flatten() {
                    stack.push(entry.path());
                }
            }
        }
    }
    ok
}

#[cfg(not(unix))]
pub(crate) fn lchown_tree(_path: &Path, _uid: u32, _gid: u32) -> bool {
    false
}

/// Install the staged artifact at `staged` into `<work>/<rel>`.
///
/// `staged` lives in a directory this process created outside the worktree's
/// namespace of tenant paths; `rel` has already been validated as a relative
/// path with no `..`. On Unix every component is opened with
/// `O_DIRECTORY|O_NOFOLLOW` and the payload is moved with `renameat`, so a
/// symlink planted anywhere in the destination path (the checkout may contain
/// one, and a parallel job's artifact may install one) makes the install fail
/// instead of writing through it. The final component is replaced, never
/// followed.
pub(crate) fn install_artifact(staged: &Path, work: &Path, rel: &str) -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        unix::install(staged, work, rel)?;
    }
    #[cfg(not(unix))]
    {
        portable::install(staged, work, rel)?;
    }
    Ok(work.join(rel))
}

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    fn cvt(rc: i32) -> io::Result<i32> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    fn cstr(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    }

    fn open_dir(parent: RawFd, name: &CString) -> io::Result<OwnedFd> {
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        Ok(unsafe { OwnedFd::from_raw_fd(cvt(fd)?) })
    }

    fn open_root(path: &Path) -> io::Result<OwnedFd> {
        let name = cstr(path.as_os_str().as_bytes())?;
        let fd = unsafe { libc::open(name.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
        Ok(unsafe { OwnedFd::from_raw_fd(cvt(fd)?) })
    }

    fn stat_no_follow(dir: RawFd, name: &CString) -> io::Result<Option<libc::stat>> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
        if rc == 0 {
            return Ok(Some(stat));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(error)
        }
    }

    fn is_dir(stat: &libc::stat) -> bool {
        stat.st_mode & libc::S_IFMT == libc::S_IFDIR
    }

    fn rename(dir: RawFd, from: &CString, to: RawFd, to_name: &CString) -> io::Result<()> {
        cvt(unsafe { libc::renameat(dir, from.as_ptr(), to, to_name.as_ptr()) }).map(|_| ())
    }

    fn unlink(dir: RawFd, name: &CString) -> io::Result<()> {
        cvt(unsafe { libc::unlinkat(dir, name.as_ptr(), 0) }).map(|_| ())
    }

    fn component_error(component: &str, error: io::Error) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("artifact path component `{component}` is not a real directory: {error}"),
        )
    }

    pub(super) fn install(staged: &Path, work: &Path, rel: &str) -> io::Result<()> {
        let root = open_root(work)?;
        let mut dir = root.try_clone()?;
        let components: Vec<&str> = rel
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect();
        let Some((last, parents)) = components.split_last() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact path is empty",
            ));
        };
        for component in parents {
            if *component == ".." {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "artifact path escapes the worktree",
                ));
            }
            let name = cstr(component.as_bytes())?;
            match open_dir(dir.as_raw_fd(), &name) {
                Ok(next) => dir = next,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    cvt(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) })?;
                    dir = open_dir(dir.as_raw_fd(), &name)
                        .map_err(|error| component_error(component, error))?;
                }
                Err(error) => return Err(component_error(component, error)),
            }
        }
        if *last == ".." {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact path escapes the worktree",
            ));
        }
        let last_name = cstr(last.as_bytes())?;
        let staged_dir = open_root(staged.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "staged artifact has no parent")
        })?)?;
        let payload_name = cstr(
            staged
                .file_name()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "staged artifact has no name")
                })?
                .as_bytes(),
        )?;

        match stat_no_follow(dir.as_raw_fd(), &last_name)? {
            None => {}
            Some(stat) if is_dir(&stat) => {
                // Move the old directory aside inside the same (verified)
                // parent, so deleting it cannot follow a symlink out of the
                // worktree; then rename the fresh payload into the free name.
                let (trash_name, trash) = unique_trash(dir.as_raw_fd(), last)?;
                rename(dir.as_raw_fd(), &last_name, dir.as_raw_fd(), &trash_name)?;
                let _ = std::fs::remove_dir_all(path_join(work, parents, trash));
            }
            Some(_) => {
                // A file or a symlink: remove the entry itself, never its target.
                unlink(dir.as_raw_fd(), &last_name)?;
            }
        }
        rename(
            staged_dir.as_raw_fd(),
            &payload_name,
            dir.as_raw_fd(),
            &last_name,
        )
    }

    /// First `"<last>.ryuz-workflow-trash-<pid>[-N]"` that does not exist in
    /// `dir`, with its path name for deletion.
    fn unique_trash(dir: RawFd, last: &str) -> io::Result<(CString, String)> {
        let mut suffix = 0u32;
        loop {
            let candidate = if suffix == 0 {
                format!("{last}.ryuz-workflow-trash-{}", std::process::id())
            } else {
                format!("{last}.ryuz-workflow-trash-{}-{suffix}", std::process::id())
            };
            let name = cstr(candidate.as_bytes())?;
            if stat_no_follow(dir, &name)?.is_none() {
                return Ok((name, candidate));
            }
            suffix += 1;
            if suffix > 1000 {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "no free trash name next to the artifact",
                ));
            }
        }
    }

    fn path_join(work: &Path, parents: &[&str], last: String) -> PathBuf {
        let mut path = work.to_path_buf();
        for parent in parents {
            path.push(parent);
        }
        path.push(last);
        path
    }
}

#[cfg(not(unix))]
mod portable {
    use std::io;
    use std::path::Path;

    /// Windows has no dirfd-relative rename in `std`; check every component and
    /// refuse symlinks, then let `rename` replace the final entry. The worktree
    /// is not modified concurrently by anything but this process (artifact
    /// installs are serialized by the runner), so the check is sufficient here.
    pub(super) fn install(staged: &Path, work: &Path, rel: &str) -> io::Result<()> {
        let mut target = work.to_path_buf();
        let components: Vec<&str> = rel
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect();
        let Some((last, parents)) = components.split_last() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact path is empty",
            ));
        };
        for component in parents {
            if *component == ".." {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "artifact path escapes the worktree",
                ));
            }
            target.push(component);
            match std::fs::symlink_metadata(&target) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("artifact path component `{component}` is a symlink"),
                    ));
                }
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("artifact path component `{component}` is not a directory"),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std::fs::create_dir(&target)?;
                }
                Err(error) => return Err(error),
            }
        }
        target.push(last);
        match std::fs::symlink_metadata(&target) {
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&target)?,
            Ok(_) => {
                std::fs::remove_file(&target)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        std::fs::rename(staged, &target)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ryuz-workflow-fs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn lchown_tree_walks_without_following_links() {
        let dir = temp("lchown");
        std::fs::create_dir_all(dir.join("nested")).expect("temp dir");
        std::fs::write(dir.join("nested/file"), "x").expect("file");
        std::fs::write(dir.join("link"), "y").expect("file");
        std::os::unix::fs::symlink("/etc/passwd", dir.join("dangling")).expect("symlink");

        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).expect("meta"));
        assert!(lchown_tree(&dir, uid, uid));
        let link = std::fs::symlink_metadata(dir.join("dangling")).expect("link meta");
        assert!(link.file_type().is_symlink());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_a_symlinked_parent() {
        let work = temp("install-symlink");
        let outside = temp("install-outside");
        std::fs::create_dir_all(work.join("staging")).expect("staging");
        std::fs::write(work.join("staging/payload"), "artifact").expect("payload");
        std::os::unix::fs::symlink(&outside, work.join("reports")).expect("symlink");

        let error = install_artifact(&work.join("staging/payload"), &work, "reports/junit.xml")
            .expect_err("symlinked parent");
        assert!(error.to_string().contains("reports"), "{error}");
        assert!(
            !outside.join("junit.xml").exists(),
            "wrote through the symlink"
        );
        let _ = std::fs::remove_dir_all(&work);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn install_creates_parents_and_replaces_entries() {
        let work = temp("install");
        std::fs::create_dir_all(work.join("staging")).expect("staging");
        std::fs::write(work.join("staging/payload"), "new").expect("payload");
        let installed =
            install_artifact(&work.join("staging/payload"), &work, "nested/dir/file.txt")
                .expect("install");
        assert_eq!(std::fs::read_to_string(&installed).expect("read"), "new");

        std::fs::write(work.join("staging/payload"), "next").expect("payload");
        install_artifact(&work.join("staging/payload"), &work, "nested/dir/file.txt")
            .expect("replace file");
        assert_eq!(std::fs::read_to_string(&installed).expect("read"), "next");

        // A symlink at the destination is replaced, not followed.
        std::os::unix::fs::symlink("/etc/passwd", work.join("victim")).expect("symlink");
        std::fs::write(work.join("staging/payload"), "safe").expect("payload");
        install_artifact(&work.join("staging/payload"), &work, "victim").expect("replace link");
        let meta = std::fs::symlink_metadata(work.join("victim")).expect("meta");
        assert!(!meta.file_type().is_symlink());
        assert_eq!(
            std::fs::read_to_string(work.join("victim")).expect("read"),
            "safe"
        );
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn install_replaces_an_existing_directory() {
        let work = temp("install-dir");
        std::fs::create_dir_all(work.join("dist/old")).expect("old dist");
        std::fs::write(work.join("dist/old/file"), "stale").expect("stale");
        std::fs::create_dir_all(work.join("staging/payload/sub")).expect("staged");
        std::fs::write(work.join("staging/payload/sub/file"), "fresh").expect("fresh");
        install_artifact(&work.join("staging/payload"), &work, "dist").expect("replace dir");
        assert!(work.join("dist/sub/file").exists());
        assert!(!work.join("dist/old").exists());
        let _ = std::fs::remove_dir_all(&work);
    }
}
