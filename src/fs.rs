use std::{
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use anyhow::Context;
use serde::Serialize;
use tokio::fs;

#[derive(Debug, Clone, Serialize)]
pub struct FsRoot {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FsEntryKind {
    Dir,
    File,
}

#[derive(Debug, Clone, Serialize)]
pub struct FsEntry {
    pub name: String,
    pub path: String,
    pub kind: FsEntryKind,
    pub size_bytes: Option<u64>,
    pub modified_at_ms: Option<u64>,
}

pub fn roots() -> Vec<FsRoot> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));

    let candidates = [
        ("Home", home.clone()),
        ("Desktop", home.join("Desktop")),
        ("Downloads", home.join("Downloads")),
        ("Documents", home.join("Documents")),
    ];

    let mut out = Vec::new();
    for (name, p) in candidates {
        if p.is_dir() {
            out.push(FsRoot {
                name: name.to_string(),
                path: p.to_string_lossy().to_string(),
            });
        }
    }

    if out.is_empty() {
        out.push(FsRoot {
            name: "Current".to_string(),
            path: ".".to_string(),
        });
    }

    out
}

pub async fn list_dir(path: &Path) -> anyhow::Result<Vec<FsEntry>> {
    let mut rd = fs::read_dir(path)
        .await
        .with_context(|| format!("read dir {}", path.display()))?;

    let mut out = Vec::new();
    while let Some(ent) = rd.next_entry().await.context("read dir entry")? {
        let name = ent.file_name().to_string_lossy().to_string();
        if name == "." || name == ".." {
            continue;
        }

        let p = ent.path();
        let md = ent.metadata().await.ok();
        let kind = match md.as_ref().map(|m| m.is_dir()) {
            Some(true) => FsEntryKind::Dir,
            _ => FsEntryKind::File,
        };
        let size_bytes = md.as_ref().and_then(|m| if m.is_file() { Some(m.len()) } else { None });
        let modified_at_ms = md
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64);

        out.push(FsEntry {
            name,
            path: p.to_string_lossy().to_string(),
            kind,
            size_bytes,
            modified_at_ms,
        });
    }

    // Sort: dirs first, then name.
    out.sort_by(|a, b| match (&a.kind, &b.kind) {
        (FsEntryKind::Dir, FsEntryKind::File) => std::cmp::Ordering::Less,
        (FsEntryKind::File, FsEntryKind::Dir) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    Ok(out)
}
