use crate::{
    api::Api,
    store::{Local, read_private},
};
use anyhow::{Context, Result, ensure};
use niceotp_protocol::{AuthConfig, SessionRequest, SessionResponse};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use reqwest::Method;
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

pub async fn login(
    s: &Local,
    token_file: Option<&Path>,
    no_browser: bool,
) -> Result<SessionResponse> {
    let api = Api::new(s)?;
    let token = if let Some(path) = token_file {
        Zeroizing::new(
            String::from_utf8(read_private(path, 16384)?.to_vec())?
                .trim()
                .to_string(),
        )
    } else {
        let cfg: AuthConfig = api
            .call::<(), _>(Method::GET, "/v1/auth/config", None)
            .await?;
        let issuer = url::Url::parse(&cfg.issuer)?;
        ensure!(
            issuer.scheme() == "https"
                || (issuer.scheme() == "http"
                    && matches!(issuer.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))),
            "OIDC requires HTTPS except loopback"
        );
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()?;
        let metadata = CoreProviderMetadata::discover_async(IssuerUrl::new(cfg.issuer)?, &client)
            .await
            .map_err(|_| anyhow::anyhow!("OIDC discovery failed"))?;
        for endpoint in [
            Some(metadata.authorization_endpoint().url()),
            metadata.token_endpoint().map(|v| v.url()),
            Some(metadata.jwks_uri().url()),
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                endpoint.scheme() == "https"
                    || (endpoint.scheme() == "http"
                        && matches!(
                            endpoint.host_str(),
                            Some("127.0.0.1" | "localhost" | "[::1]")
                        )),
                "Unsafe OIDC endpoint"
            );
        }
        let oidc = CoreClient::from_provider_metadata(metadata, ClientId::new(cfg.client_id), None)
            .set_redirect_uri(RedirectUrl::new("http://127.0.0.1:43673/callback".into())?);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:43673")
            .await
            .context("OIDC callback port 43673 is busy")?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, state, nonce) = oidc
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".into()))
            .set_pkce_challenge(challenge)
            .url();
        eprintln!("Open this login URL:\n{auth_url}");
        if !no_browser {
            let _ = webbrowser::open(auth_url.as_str());
        }
        let code=tokio::time::timeout(Duration::from_secs(180),async {
            loop {
                let (mut stream,_)=listener.accept().await?;
                let mut bytes=Vec::new();
                loop {
                    let mut b=[0u8;1024];
                    let n=tokio::time::timeout(Duration::from_secs(3),stream.read(&mut b)).await??;
                    ensure!(n>0,"Incomplete callback");bytes.extend_from_slice(&b[..n]);
                    ensure!(bytes.len()<=8192,"Callback too large");
                    if bytes.windows(4).any(|w|w==b"\r\n\r\n"){break;}
                }
                let text=String::from_utf8(bytes)?;
                let first=text.lines().next().context("Invalid callback")?;
                let pieces:Vec<_>=first.split_whitespace().collect();
                ensure!(pieces.len()==3 && pieces[0]=="GET","Invalid callback method");
                let target=url::Url::parse(&format!("http://127.0.0.1:43673{}",pieces[1]))?;
                let params:Vec<_>=target.query_pairs().collect();
                let states:Vec<_>=params.iter().filter(|(k,_)|k=="state").collect();
                let codes:Vec<_>=params.iter().filter(|(k,_)|k=="code").collect();
                let valid=target.path()=="/callback" && states.len()==1 && codes.len()==1 && Sha256::digest(states[0].1.as_bytes())==Sha256::digest(state.secret().as_bytes());
                let response=if valid {"HTTP/1.1 200 OK\r\nContent-Length: 37\r\nConnection: close\r\n\r\nLogin received. Return to the terminal."} else {"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"};
                stream.write_all(response.as_bytes()).await?;
                if valid {return Ok::<_,anyhow::Error>(codes[0].1.to_string());}
            }
        }).await.context("Login timed out")??;
        let response = oidc
            .exchange_code(AuthorizationCode::new(code))?
            .set_pkce_verifier(verifier)
            .request_async(&client)
            .await
            .map_err(|_| anyhow::anyhow!("OIDC code exchange failed"))?;
        let token = response.id_token().context("Provider omitted ID token")?;
        let validator = oidc.id_token_verifier();
        let claims = token
            .claims(&validator, &nonce)
            .map_err(|_| anyhow::anyhow!("OIDC token validation failed"))?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                response.access_token(),
                token.signing_alg()?,
                token.signing_key(&validator)?,
            )?;
            ensure!(*expected == actual, "OIDC access token hash mismatch");
        }
        Zeroizing::new(token.to_string())
    };
    api.call(
        Method::POST,
        "/v1/sessions",
        Some(&SessionRequest {
            id_token: token.to_string(),
        }),
    )
    .await
}
