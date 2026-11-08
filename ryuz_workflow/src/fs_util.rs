//! Small filesystem helpers the runner needs but the standard library does
//! not spell out.

use std::path::Path;

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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn lchown_tree_walks_without_following_links() {
        let dir = std::env::temp_dir().join(format!("ryuz_workflow-lchown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
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
}
