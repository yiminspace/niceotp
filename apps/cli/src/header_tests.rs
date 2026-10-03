//! Real loopback HTTP transport tests for commit-success/response-loss cases.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("niceotp-header-test-{}", Uuid::new_v4())))
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture_header() -> VaultHeader {
    // Public synthetic wrappers; these transport tests never decrypt them.
    VaultHeader {
        format_version: FORMAT_VERSION,
        vault_id: Uuid::new_v4(),
        password: PasswordEnvelope {
            kdf: KdfParams {
                salt: "public-test-salt".into(),
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 1,
            },
            sealed: Sealed {
                nonce: "public-test-nonce".into(),
                ciphertext: "public-test-ciphertext".into(),
            },
        },
        recovery: Sealed {
            nonce: "public-test-nonce".into(),
            ciphertext: "public-test-ciphertext".into(),
        },
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut bytes = Vec::new();
    loop {
        let mut buf = [0_u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
        assert!(bytes.len() < 64 * 1024);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                return (
                    header.lines().next().unwrap().to_owned(),
                    bytes[end + 4..end + 4 + length].to_vec(),
                );
            }
        }
    }
}

async fn lost_response_server(
    method: &'static str,
    expected: Value,
    returned: VaultState,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        let (request, body) = read_request(&mut first).await;
        assert_eq!(request, format!("{method} /v1/vault HTTP/1.1"));
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), expected);
        // The server "commits" expected state but loses the HTTP response.
        drop(first);
        let (mut retry, _) = listener.accept().await.unwrap();
        let (request, _) = read_request(&mut retry).await;
        assert_eq!(request, "GET /v1/vault HTTP/1.1");
        let bytes = serde_json::to_vec(&returned).unwrap();
        retry.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).as_bytes()).await.unwrap();
        retry.write_all(&bytes).await.unwrap();
        retry.shutdown().await.unwrap();
    });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn lost_header_put_response_is_reconciled_and_saved() {
    let dir = TestDir::new();
    let store = Store::open(dir.0.clone()).unwrap();
    let original = fixture_header();
    let mut desired = original.clone();
    desired.recovery.ciphertext = "new public test wrapper".into();
    let request = UpdateVault {
        base_revision: 1,
        header: desired.clone(),
    };
    let (server, task) = lost_response_server(
        "PUT",
        serde_json::to_value(request).unwrap(),
        VaultState {
            header: desired.clone(),
            revision: 2,
        },
    )
    .await;
    let mut local = Local::new(server);
    local.session = Some("public-test-session".into());
    local.vault = Some(VaultState {
        header: original,
        revision: 1,
    });
    store.save(&local).unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        replace_header(&store, &mut local, desired.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    task.await.unwrap();
    let saved = store.load(None).unwrap();
    assert!(saved.header().unwrap() == &desired);
    assert_eq!(saved.vault.unwrap().revision, 2);
}

#[tokio::test]
async fn unconfirmed_header_update_keeps_original_durable_state() {
    let dir = TestDir::new();
    let store = Store::open(dir.0.clone()).unwrap();
    let original = fixture_header();
    let mut desired = original.clone();
    desired.recovery.ciphertext = "new public test wrapper".into();
    let request = UpdateVault {
        base_revision: 1,
        header: desired.clone(),
    };
    let (server, task) = lost_response_server(
        "PUT",
        serde_json::to_value(request).unwrap(),
        VaultState {
            header: original.clone(),
            revision: 1,
        },
    )
    .await;
    let mut local = Local::new(server);
    local.session = Some("public-test-session".into());
    local.vault = Some(VaultState {
        header: original.clone(),
        revision: 1,
    });
    store.save(&local).unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            replace_header(&store, &mut local, desired)
        )
        .await
        .unwrap()
        .is_err()
    );
    task.await.unwrap();
    assert!(store.load(None).unwrap().header().unwrap() == &original);
}

#[tokio::test]
async fn lost_vault_creation_response_is_reconciled_and_saved() {
    let dir = TestDir::new();
    let store = Store::open(dir.0.clone()).unwrap();
    let header = fixture_header();
    let (server, task) = lost_response_server(
        "POST",
        serde_json::to_value(&header).unwrap(),
        VaultState {
            header: header.clone(),
            revision: 1,
        },
    )
    .await;
    let mut local = Local::new(server);
    local.session = Some("public-test-session".into());
    local.vault = Some(VaultState {
        header: header.clone(),
        revision: 0,
    });
    store.save(&local).unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        publish(&store, &mut local),
    )
    .await
    .unwrap()
    .unwrap();
    task.await.unwrap();
    let saved = store.load(None).unwrap();
    assert!(saved.header().unwrap() == &header);
    assert_eq!(saved.vault.unwrap().revision, 1);
}
