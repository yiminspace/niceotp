use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use niceotp_protocol::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Local {
    pub format_version: u32,
    pub server: String,
    pub account_id: Option<Uuid>,
    pub session: Option<String>,
    #[serde(default)]
    pub remembered: bool,
    pub vault: Option<VaultState>,
    pub cursor: i64,
    pub items: BTreeMap<Uuid, ServerItem>,
    pub pending: Vec<Mutation>,
    pub conflicts: Vec<Conflict>,
    pub inflight: Option<SyncRequest>,
}
impl Local {
    pub fn new(server: String) -> Self {
        Self {
            format_version: 1,
            server,
            account_id: None,
            session: None,
            remembered: false,
            vault: None,
            cursor: 0,
            items: BTreeMap::new(),
            pending: vec![],
            conflicts: vec![],
            inflight: None,
        }
    }
    pub fn header(&self) -> Result<&VaultHeader> {
        Ok(&self
            .vault
            .as_ref()
            .context("No local vault. Run init or sync first.")?
            .header)
    }
    pub fn working(&self) -> BTreeMap<Uuid, ServerItem> {
        let mut all = self.items.clone();
        for p in &self.pending {
            all.insert(
                p.id,
                ServerItem {
                    id: p.id,
                    revision: p.base_revision,
                    payload: p.payload.clone(),
                },
            );
        }
        all
    }
    pub fn queue(&mut self, id: Uuid, payload: Option<Sealed>) -> Result<()> {
        ensure!(
            self.inflight.is_none(),
            "An earlier sync has an uncertain result. Retry sync before editing."
        );
        ensure!(
            !self.conflicts.iter().any(|c| c.mutation.id == id),
            "Resolve this item's conflict before editing."
        );
        ensure!(
            self.items.get(&id).is_none_or(|i| i.payload.is_some()),
            "Permanently deleted IDs cannot be reused."
        );
        let base = self.items.get(&id).map_or(0, |i| i.revision);
        self.pending.retain(|p| p.id != id);
        // An unsynchronized creation can be discarded locally without emitting a deletion.
        if base != 0 || payload.is_some() {
            self.pending.push(Mutation {
                mutation_id: Uuid::new_v4(),
                id,
                base_revision: base,
                payload,
            });
        }
        Ok(())
    }
}
pub struct Store {
    pub dir: PathBuf,
    _lock: File,
}
impl Store {
    pub fn open(dir: PathBuf) -> Result<Self> {
        if dir.exists() {
            ensure!(
                !fs::symlink_metadata(&dir)?.file_type().is_symlink(),
                "Profile directory must not be a symlink"
            );
        }
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        let p = dir.join("lock");
        if p.exists() {
            ensure!(
                !fs::symlink_metadata(&p)?.file_type().is_symlink(),
                "Profile lock must not be a symlink"
            );
        }
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let lock = opts.open(p)?;
        lock.try_lock_exclusive()
            .context("Another niceotp command is using this profile")?;
        Ok(Self { dir, _lock: lock })
    }
    pub fn load(&self, server: Option<&str>) -> Result<Local> {
        let p = self.dir.join("state.json");
        if !p.exists() {
            return Ok(Local::new(
                server
                    .unwrap_or("http://127.0.0.1:8080")
                    .trim_end_matches('/')
                    .into(),
            ));
        }
        let bytes = read_private(&p, 64 * 1024 * 1024)?;
        let state: Local = serde_json::from_slice(&bytes).context("Invalid profile state")?;
        ensure!(state.format_version == 1, "Unsupported profile version");
        if let Some(server) = server {
            ensure!(
                server.trim_end_matches('/') == state.server,
                "Use a new --data-dir for a different server"
            );
        }
        Ok(state)
    }
    pub fn save(&self, state: &Local) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(state)?);
        let tmp = self.dir.join(format!("state-{}.tmp", Uuid::new_v4()));
        write_new_private(&tmp, &bytes)?;
        fs::rename(&tmp, self.dir.join("state.json"))?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
    pub fn keyring(&self, vault_id: Uuid) -> Result<keyring::Entry> {
        let path = fs::canonicalize(&self.dir)?;
        Ok(keyring::Entry::new(
            "niceotp-v1",
            &format!("{}:{vault_id}", path.display()),
        )?)
    }
}
pub fn read_private(path: &Path, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "Expected a regular private file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "Sensitive file must have permissions 0600"
        );
    }
    ensure!(meta.len() <= max, "File is too large");
    let mut out = Zeroizing::new(Vec::new());
    File::open(path)?.take(max + 1).read_to_end(&mut out)?;
    ensure!(out.len() as u64 <= max, "File is too large");
    Ok(out)
}
pub fn write_new_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .context("Cannot create output file (existing files are never overwritten)")?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
