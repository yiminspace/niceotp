mod api;
mod login;
mod store;
use anyhow::{Context, Result, ensure};
use api::Api;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand, ValueEnum};
use niceotp_protocol::*;
use niceotp_vault::*;
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Read},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use store::{Local, Store, read_private, write_new_private};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "End-to-end encrypted OTP vault. Login and vault unlocking are separate."
)]
struct Args {
    /// Separate device/profile directory. Local secrets are encrypted; session files are private.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    server: Option<String>,
    /// Read the vault password from a private (0600) file. Otherwise prompt without echo.
    #[arg(long, global = true, env = "NICEOTP_PASSWORD_FILE")]
    password_file: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Sign in through OIDC authorization code + PKCE using your browser.
    Login {
        #[arg(long)]
        no_browser: bool,
        #[arg(long)]
        id_token_file: Option<PathBuf>,
    },
    Logout,
    /// Create an encrypted vault and save its recovery code to a new private file.
    Init {
        #[arg(long)]
        recovery_output: PathBuf,
    },
    Sync,
    Status,
    Doctor,
    /// Cache a validated vault key in the OS keyring. No plaintext fallback.
    Unlock {
        #[arg(long)]
        remember: bool,
    },
    Lock,
    /// Read an otpauth:// URI from stdin without putting it in process arguments.
    Add,
    /// Import newline-separated otpauth:// URIs from stdin.
    Import,
    List {
        #[arg(long)]
        trash: bool,
        #[arg(long)]
        query: Option<String>,
    },
    Show {
        id: Uuid,
        #[arg(long)]
        reveal: bool,
    },
    Code {
        id: Uuid,
        #[arg(long)]
        at: Option<u64>,
    },
    Edit {
        id: Uuid,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        issuer: Option<String>,
    },
    Pin {
        id: Uuid,
        #[arg(long)]
        off: bool,
    },
    Delete {
        id: Uuid,
    },
    Restore {
        id: Uuid,
    },
    Purge {
        id: Uuid,
        #[arg(long)]
        yes: bool,
    },
    Conflicts {
        #[arg(long)]
        reveal: bool,
    },
    Resolve {
        id: Uuid,
        #[arg(long, value_enum)]
        use_version: Choice,
    },
    Backup {
        output: PathBuf,
    },
    /// Offline recovery into an empty profile; sync later to publish to a fresh account/server.
    RestoreBackup {
        input: PathBuf,
        #[arg(long)]
        recovery_file: Option<PathBuf>,
    },
    SetPassword {
        #[arg(long)]
        new_password_file: Option<PathBuf>,
    },
    Recover {
        #[arg(long)]
        recovery_file: PathBuf,
        #[arg(long)]
        new_password_file: Option<PathBuf>,
    },
    RotateRecovery {
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Clone, ValueEnum)]
enum Choice {
    Local,
    Remote,
}
fn secret(path: Option<&PathBuf>, prompt: &str) -> Result<Zeroizing<String>> {
    if let Some(p) = path {
        return Ok(Zeroizing::new(
            String::from_utf8(read_private(p, 4096)?.to_vec())?
                .trim_end_matches(['\r', '\n'])
                .to_string(),
        ));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}
fn new_password(path: Option<&PathBuf>) -> Result<Zeroizing<String>> {
    let first = secret(path, "New vault password: ")?;
    if path.is_none() {
        let again = secret(None, "Confirm vault password: ")?;
        ensure!(*first == *again, "Passwords do not match");
    }
    ensure!(
        first.len() >= 12,
        "Use a vault password of at least 12 characters (prefer a long random passphrase)"
    );
    Ok(first)
}
fn key(args: &Args, store: &Store, s: &Local) -> Result<VaultKey> {
    let header = s.header()?;
    if s.remembered
        && args.password_file.is_none()
        && let Ok(entry) = store.keyring(header.vault_id)
        && let Ok(value) = entry.get_password()
    {
        let value = Zeroizing::new(value);
        if let Some(key) = authenticated_cached_key(&value, s) {
            return Ok(key);
        }
    }
    // A key wrapper cannot confirm a cached key without its wrapping secret.
    // With no authenticated record, or after cache corruption, verify a password.
    let password = secret(args.password_file.as_ref(), "Vault password: ")?;
    Ok(unlock_password(header, &password)?)
}
fn authenticated_cached_key(value: &str, s: &Local) -> Option<VaultKey> {
    if value.len() != 43 {
        return None;
    }
    let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(value.as_bytes()).ok()?);
    let bytes: [u8; 32] = raw.as_slice().try_into().ok()?;
    let key = VaultKey::from_bytes(bytes);
    let vault_id = s.header().ok()?.vault_id;
    // Prefer persisted records, then an unsynced creation. Never write or rotate
    // a wrapper under a cached key that has not authenticated existing data.
    let record = s
        .items
        .values()
        .find_map(|item| item.payload.as_ref().map(|payload| (item.id, payload)))
        .or_else(|| {
            s.pending
                .iter()
                .find_map(|item| item.payload.as_ref().map(|payload| (item.id, payload)))
        })
        .or_else(|| {
            s.conflicts.iter().find_map(|conflict| {
                conflict
                    .mutation
                    .payload
                    .as_ref()
                    .map(|payload| (conflict.mutation.id, payload))
            })
        });
    let (id, payload) = record?;
    decrypt_entry(&key, vault_id, id, payload).ok()?;
    Some(key)
}
fn read_entry(s: &Local, k: &VaultKey, id: Uuid) -> Result<Entry> {
    let all = s.working();
    let item = all.get(&id).context("Unknown item ID")?;
    let sealed = item
        .payload
        .as_ref()
        .context("Item is permanently deleted")?;
    Ok(decrypt_entry(k, s.header()?.vault_id, id, sealed)?)
}
fn summary(id: Uuid, e: &Entry) -> Value {
    json!({"id":id,"name":e.name,"account":e.account,"issuer":e.issuer,"algorithm":e.algorithm,"digits":e.digits,"period":e.period,"pinned":e.pinned,"trashed":e.trashed})
}
fn forget(store: &Store, s: &mut Local) -> Result<()> {
    if !s.remembered {
        return Ok(());
    }
    if let Some(v) = &s.vault {
        match store.keyring(v.header.vault_id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(e.into()),
        }
    }
    s.remembered = false;
    store.save(s)?;
    Ok(())
}
#[tokio::main]
async fn main() {
    let args = Args::parse();
    match run(&args).await {
        Ok(value) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string(&value).expect("serializable output")
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("serializable output")
                );
            }
        }
        Err(error) => {
            if args.json {
                eprintln!("{}", json!({"error":error.to_string()}));
            } else {
                eprintln!("Error: {error}");
            }
            std::process::exit(1);
        }
    }
}
async fn run(args: &Args) -> Result<Value> {
    let dir = args.data_dir.clone().unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share/niceotp")
    });
    let store = Store::open(dir)?;
    let mut s = store.load(args.server.as_deref())?;
    match &args.command {
        Command::Login {
            no_browser,
            id_token_file,
        } => {
            let session = login::login(&s, id_token_file.as_deref(), *no_browser).await?;
            if let Some(account) = s.account_id {
                ensure!(
                    account == session.account_id,
                    "Different account: use a new --data-dir to avoid mixing vaults"
                );
            }
            s.account_id = Some(session.account_id);
            s.session = Some(session.access_token);
            store.save(&s)?;
            Ok(json!({"logged_in":true,"expires_at":session.expires_at}))
        }
        Command::Logout => {
            let _: Value = Api::new(&s)?
                .call::<(), _>(Method::DELETE, "/v1/session", None)
                .await?;
            s.session = None;
            store.save(&s)?;
            forget(&store, &mut s)?;
            Ok(json!({"logged_in":false}))
        }
        Command::Init { recovery_output } => {
            ensure!(s.vault.is_none(), "Profile already has a vault");
            ensure!(s.session.is_some(), "Log in first");
            let password = new_password(args.password_file.as_ref())?;
            let (header, _, recovery) = create_vault(&password)?;
            let recovery = Zeroizing::new(recovery);
            write_new_private(recovery_output, recovery.as_bytes())?;
            let saved = secret(Some(recovery_output), "")?;
            unlock_recovery(&header, &saved)?;
            s.vault = Some(VaultState {
                header,
                revision: 0,
            });
            store.save(&s)?;
            publish(&store, &mut s).await?;
            Ok(
                json!({"created":true,"recovery_file":recovery_output,"instruction":"Store the recovery file separately from this device and your vault backups."}),
            )
        }
        Command::Sync => {
            if s.vault.as_ref().is_some_and(|v| v.revision == 0) {
                publish(&store, &mut s).await?;
            }
            let mut total = 0;
            loop {
                let result = api::sync(&store, &mut s).await?;
                total += result.applied.len();
                if s.pending.is_empty() {
                    break;
                }
            }
            Ok(
                json!({"cursor":s.cursor,"applied":total,"conflicts":s.conflicts.len(),"pending":s.pending.len()}),
            )
        }
        Command::Status => Ok(
            json!({"server":s.server,"logged_in":s.session.is_some(),"vault_id":s.vault.as_ref().map(|v|v.header.vault_id),"cursor":s.cursor,"pending":s.pending.len(),"conflicts":s.conflicts.len(),"uncertain_sync":s.inflight.is_some()}),
        ),
        Command::Doctor => {
            let health: Value = Api::new(&s)?
                .call::<(), _>(Method::GET, "/health", None)
                .await?;
            Ok(
                json!({"health":health,"profile":store.dir,"protocol_version":FORMAT_VERSION,"encryption":"client-only","independently_audited":false}),
            )
        }
        Command::Unlock { remember } => {
            let k = key(args, &store, &s)?;
            if *remember {
                let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(k.as_bytes()));
                store
                    .keyring(s.header()?.vault_id)?
                    .set_password(&encoded)
                    .context("OS keyring failed; no key was saved to a plaintext fallback")?;
                s.remembered = true;
                store.save(&s)?;
            }
            Ok(json!({"unlocked":true,"remembered":remember}))
        }
        Command::Lock => {
            forget(&store, &mut s)?;
            Ok(json!({"locked":true}))
        }
        Command::Add | Command::Import => {
            let k = key(args, &store, &s)?;
            let mut uri = Zeroizing::new(String::new());
            if io::stdin().is_terminal() {
                uri = Zeroizing::new(rpassword::prompt_password("OTP URI (hidden): ")?);
            } else {
                io::stdin().take(1024 * 1024 + 1).read_to_string(&mut uri)?;
            }
            ensure!(uri.len() <= 1024 * 1024, "Import too large");
            let entries: Vec<Entry> = if matches!(args.command, Command::Import) {
                uri.lines()
                    .filter(|v| !v.trim().is_empty())
                    .map(|v| Entry::from_uri(v.trim()))
                    .collect::<std::result::Result<_, _>>()?
            } else {
                vec![Entry::from_uri(uri.trim())?]
            };
            ensure!(
                !entries.is_empty() && entries.len() <= 1000,
                "Import requires 1 to 1000 entries"
            );
            let mut added = Vec::new();
            for entry in entries {
                let id = Uuid::new_v4();
                s.queue(
                    id,
                    Some(encrypt_entry(&k, s.header()?.vault_id, id, &entry)?),
                )?;
                added.push(summary(id, &entry));
            }
            store.save(&s)?;
            if matches!(args.command, Command::Add) {
                Ok(added.remove(0))
            } else {
                Ok(json!({"items":added}))
            }
        }

        Command::List { trash, query } => {
            let k = key(args, &store, &s)?;
            let mut entries = Vec::new();
            for (id, item) in s.working() {
                if let Some(p) = item.payload {
                    let e = decrypt_entry(&k, s.header()?.vault_id, id, &p)?;
                    if e.trashed != *trash {
                        continue;
                    }
                    if let Some(q) = query {
                        let text = format!("{} {} {}", e.name, e.account, e.issuer).to_lowercase();
                        if !text.contains(&q.to_lowercase()) {
                            continue;
                        }
                    }
                    entries.push(summary(id, &e));
                }
            }
            entries.sort_by_key(|e| {
                (
                    !e["pinned"].as_bool().unwrap_or(false),
                    e["name"].as_str().unwrap_or("").to_owned(),
                )
            });
            Ok(json!({"items":entries,"conflicts":s.conflicts.len()}))
        }
        Command::Show { id, reveal } => {
            let k = key(args, &store, &s)?;
            let e = read_entry(&s, &k, *id)?;
            let mut v = summary(*id, &e);
            if *reveal {
                v["secret"] = json!(e.secret);
            }
            Ok(v)
        }
        Command::Code { id, at } => {
            let k = key(args, &store, &s)?;
            let e = read_entry(&s, &k, *id)?;
            ensure!(!e.trashed, "Restore this item from trash first");
            let now = at.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
            Ok(json!({"id":id,"code":e.code_at(now)?,"valid_for_seconds":e.period-now%e.period}))
        }
        Command::Edit {
            id,
            name,
            account,
            issuer,
        } => {
            let k = key(args, &store, &s)?;
            let mut e = read_entry(&s, &k, *id)?;
            if let Some(v) = name {
                e.name = v.clone();
            }
            if let Some(v) = account {
                e.account = v.clone();
            }
            if let Some(v) = issuer {
                e.issuer = v.clone();
            }
            e.validate()?;
            s.queue(*id, Some(encrypt_entry(&k, s.header()?.vault_id, *id, &e)?))?;
            store.save(&s)?;
            Ok(summary(*id, &e))
        }
        Command::Pin { id, .. } | Command::Delete { id } | Command::Restore { id } => {
            let k = key(args, &store, &s)?;
            let mut e = read_entry(&s, &k, *id)?;
            match args.command {
                Command::Pin { off, .. } => e.pinned = !off,
                Command::Delete { .. } => e.trashed = true,
                _ => e.trashed = false,
            }
            s.queue(*id, Some(encrypt_entry(&k, s.header()?.vault_id, *id, &e)?))?;
            store.save(&s)?;
            Ok(summary(*id, &e))
        }
        Command::Purge { id, yes } => {
            ensure!(*yes, "Permanent deletion requires --yes");
            let k = key(args, &store, &s)?;
            let e = read_entry(&s, &k, *id)?;
            ensure!(
                e.trashed,
                "Move this item to trash before permanently deleting"
            );
            s.queue(*id, None)?;
            store.save(&s)?;
            Ok(json!({"purged":id}))
        }
        Command::Conflicts { reveal } => {
            let k = key(args, &store, &s)?;
            let mut out = Vec::new();
            for c in &s.conflicts {
                let describe = |p: &Option<Sealed>| -> Result<Value> {
                    if let Some(p) = p {
                        let e = decrypt_entry(&k, s.header()?.vault_id, c.mutation.id, p)?;
                        let mut v = summary(c.mutation.id, &e);
                        if *reveal {
                            v["secret"] = json!(e.secret);
                        }
                        Ok(v)
                    } else {
                        Ok(json!({"permanently_deleted":true}))
                    }
                };
                out.push(json!({"id":c.mutation.id,"local":describe(&c.mutation.payload)?,"remote":c.current.as_ref().map(|r|describe(&r.payload)).transpose()?}));
            }
            Ok(json!({"conflicts":out}))
        }
        Command::Resolve { id, use_version } => {
            ensure!(
                s.inflight.is_none(),
                "Retry uncertain sync before resolving conflicts"
            );
            let c = s
                .conflicts
                .iter()
                .find(|c| c.mutation.id == *id)
                .context("No conflict for this ID")?
                .clone();
            if matches!(use_version, Choice::Local) {
                ensure!(
                    c.current.as_ref().is_none_or(|r| r.payload.is_some()),
                    "Remote permanently deleted this ID; re-import as a new item if needed"
                );
            }
            s.conflicts.retain(|c| c.mutation.id != *id);
            if let Some(current) = c.current {
                s.items.insert(*id, current);
            } else {
                s.items.remove(id);
            }
            if matches!(use_version, Choice::Local) {
                s.queue(*id, c.mutation.payload)?;
            }
            store.save(&s)?;
            Ok(json!({"resolved":id,"pending":s.pending.len()}))
        }
        Command::Backup { output } => {
            ensure!(
                s.conflicts.is_empty() && s.inflight.is_none(),
                "Resolve conflicts and uncertain sync before backup"
            );
            let k = key(args, &store, &s)?;
            let backup = Backup {
                format_version: FORMAT_VERSION,
                header: s.header()?.clone(),
                items: s.working().into_values().collect(),
            };
            let bytes = export_backup(&k, &backup)?;
            write_new_private(output, &bytes)?;
            Ok(json!({"backup":output,"items":backup.items.len()}))
        }
        Command::RestoreBackup {
            input,
            recovery_file,
        } => {
            ensure!(
                s.vault.is_none(),
                "Use an empty --data-dir for backup restoration"
            );
            let bytes = read_private(input, 64 * 1024 * 1024)?;
            let (backup, k) = if let Some(p) = recovery_file {
                let recovery = secret(Some(p), "")?;
                import_backup_recovery(&bytes, &recovery)?
            } else {
                let password = secret(args.password_file.as_ref(), "Backup vault password: ")?;
                import_backup_password(&bytes, &password)?
            };
            let vault_id = backup.header.vault_id;
            s.vault = Some(VaultState {
                header: backup.header,
                revision: 0,
            });
            s.items = BTreeMap::new();
            s.cursor = 0;
            for item in backup.items {
                if let Some(p) = item.payload {
                    let e = decrypt_entry(&k, vault_id, item.id, &p)?;
                    let id = Uuid::new_v4();
                    s.queue(id, Some(encrypt_entry(&k, vault_id, id, &e)?))?;
                }
            }
            store.save(&s)?;
            Ok(
                json!({"restored":s.pending.len(),"offline":true,"instruction":"Log in to a fresh account/server and sync when ready."}),
            )
        }
        Command::SetPassword { new_password_file }
        | Command::Recover {
            new_password_file, ..
        } => {
            ensure!(s.inflight.is_none(), "Retry uncertain sync first");
            let k = if let Command::Recover { recovery_file, .. } = &args.command {
                let r = secret(Some(recovery_file), "")?;
                unlock_recovery(s.header()?, &r)?
            } else {
                key(args, &store, &s)?
            };
            let password = new_password(new_password_file.as_ref())?;
            let mut header = s.header()?.clone();
            change_password(&mut header, &k, &password)?;
            replace_header(&store, &mut s, header).await?;
            Ok(json!({"password_changed":true,"old_backups_unchanged":true}))
        }
        Command::RotateRecovery { output } => {
            let k = key(args, &store, &s)?;
            let mut header = s.header()?.clone();
            let r = Zeroizing::new(change_recovery(&mut header, &k)?);
            write_new_private(output, r.as_bytes())?;
            replace_header(&store, &mut s, header).await?;
            Ok(json!({"recovery_file":output,"old_backups_unchanged":true}))
        }
    }
}
async fn publish(store: &Store, s: &mut Local) -> Result<()> {
    ensure!(s.session.is_some(), "Log in before publishing the vault");
    let api = Api::new(s)?;
    let header = s.header()?.clone();
    let created: Result<VaultState> = api.call(Method::POST, "/v1/vault", Some(&header)).await;
    let state = match created {
        Ok(v) => v,
        Err(error) => {
            let current: Result<VaultState> =
                api.call::<(), _>(Method::GET, "/v1/vault", None).await;
            match current {
                Ok(v) if v.header == header => v,
                _ => return Err(error),
            }
        }
    };
    ensure!(
        state.header == header && state.revision > 0,
        "Server returned an invalid or different vault header"
    );
    s.vault = Some(state);
    store.save(s)
}
async fn replace_header(store: &Store, s: &mut Local, header: VaultHeader) -> Result<()> {
    let old = s.vault.as_ref().context("No vault")?;
    if old.revision == 0 {
        s.vault = Some(VaultState {
            header,
            revision: 0,
        });
        return store.save(s);
    }
    let request = UpdateVault {
        base_revision: old.revision,
        header,
    };
    let api = Api::new(s)?;
    let updated: Result<VaultState> = api.call(Method::PUT, "/v1/vault", Some(&request)).await;
    let state = match updated {
        Ok(state) => state,
        Err(error) => {
            // A committed PUT can lose its response. Read back the exact new
            // wrapper before reporting failure or leaving a stale local header.
            let current: Result<VaultState> =
                api.call::<(), _>(Method::GET, "/v1/vault", None).await;
            match current {
                Ok(state)
                    if state.header == request.header && state.revision > request.base_revision =>
                {
                    state
                }
                _ => {
                    return Err(error
                        .context("Vault header update was not confirmed; sync before retrying"));
                }
            }
        }
    };
    ensure!(
        state.header == request.header && state.revision > request.base_revision,
        "Server returned an invalid or different vault header"
    );
    s.vault = Some(state);
    store.save(s)
}

#[cfg(test)]
mod header_tests;

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn cached_keys_require_authenticated_vault_evidence() {
        let (header, key, _) = create_vault("test password only").unwrap();
        let mut local = Local::new("http://127.0.0.1:8080".into());
        let vault_id = header.vault_id;
        local.vault = Some(VaultState {
            header,
            revision: 1,
        });
        let encoded = URL_SAFE_NO_PAD.encode(key.as_bytes());
        assert!(authenticated_cached_key(&encoded, &local).is_none());
        let entry = Entry::from_uri("otpauth://totp/Test:a?secret=JBSWY3DPEHPK3PXP").unwrap();
        let id = Uuid::new_v4();
        local
            .queue(id, Some(encrypt_entry(&key, vault_id, id, &entry).unwrap()))
            .unwrap();
        assert_eq!(
            authenticated_cached_key(&encoded, &local)
                .unwrap()
                .as_bytes(),
            key.as_bytes()
        );
        assert!(authenticated_cached_key(&URL_SAFE_NO_PAD.encode([0_u8; 32]), &local).is_none());
        assert!(authenticated_cached_key("invalid", &local).is_none());
        let payload = local.pending[0].payload.clone();
        local.pending.clear();
        local.items.insert(
            id,
            ServerItem {
                id,
                revision: 1,
                payload,
            },
        );
        assert!(authenticated_cached_key(&encoded, &local).is_some());
        local.items.get_mut(&id).unwrap().id = Uuid::new_v4();
        assert!(authenticated_cached_key(&encoded, &local).is_none());
    }
}
