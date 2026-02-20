use std::time::Duration;

use google_gmail1::{
    Gmail,
    api::Scope,
    hyper_rustls::{self, HttpsConnector},
    hyper_util::{self, client::legacy::connect::HttpConnector},
    yup_oauth2::{self, InstalledFlowAuthenticator, InstalledFlowReturnMethod},
};
use tokio::time::sleep;

use crate::utils::Res;

pub struct GmailAPIObserver {
    client: Gmail<HttpsConnector<HttpConnector>>,
}

impl GmailAPIObserver {
    pub async fn new() -> Res<Self> {
        let secret = yup_oauth2::read_application_secret("gmail_client_secret.json").await?;

        let auth =
            InstalledFlowAuthenticator::builder(secret, InstalledFlowReturnMethod::HTTPRedirect)
                .persist_tokens_to_disk("gmail_token_cache.json") // Saves the token for future use
                .build()
                .await?;

        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(
                    hyper_rustls::HttpsConnectorBuilder::new()
                        .with_native_roots()
                        .unwrap()
                        .https_or_http()
                        .enable_http2()
                        .build(),
                );

        Ok(Self {
            client: Gmail::new(client, auth),
        })
    }
}

pub trait OTPRetriever {
    fn get_otp(&self, after_timestamp: i64) -> impl Future<Output = Res<Option<String>>>;
    fn wait_for_otp(
        &self,
        after_timestamp: i64,
        tries: usize,
    ) -> impl Future<Output = Res<Option<String>>> {
        async move {
            for i in 0..tries {
                let sleep_duration = 5 * (1 << i);
                println!("Checking OTP after {sleep_duration}s.");
                sleep(Duration::from_secs(sleep_duration)).await;

                if let Some(otp) = self.get_otp(after_timestamp).await? {
                    return Ok(Some(otp));
                }
            }

            Ok(None)
        }
    }
}

impl OTPRetriever for GmailAPIObserver {
    async fn get_otp(&self, after_timestamp: i64) -> Res<Option<String>> {
        let (_, msgs) = self
            .client
            .users()
            .messages_list("me")
            .q("from:erpkgp@adm.iitkgp.ac.in subject:\"OTP for Sign In in ERP Portal\"")
            .add_scope(Scope::Readonly)
            .max_results(1)
            .doit()
            .await?;

        if let Some(msgs) = msgs.messages {
            if let Some(msg) = msgs.first() {
                let result = self
                    .client
                    .users()
                    .messages_get("me", msg.id.as_ref().ok_or("Error: Message id not found.")?)
                    .add_scope(Scope::Metadata)
                    .format("metadata")
                    .add_metadata_headers("Subject")
                    .add_metadata_headers("Date")
                    .doit()
                    .await?;

                let headers = result
                    .1
                    .payload
                    .ok_or("Error: Message payload not found.")?
                    .headers
                    .ok_or("Error: Message headers not found.")?;

                let date = headers
                    .iter()
                    .find(|header| header.name.as_ref().is_some_and(|x| x == "Date"))
                    .ok_or("Error: Date header not found.")?;
                let date_timestamp = chrono::DateTime::parse_from_rfc2822(
                    date.value
                        .as_ref()
                        .ok_or("Error: Date header has no value")?,
                )?
                .timestamp();

                if date_timestamp < after_timestamp {
                    Ok(None)
                } else {
                    let subject = headers
                        .iter()
                        .find(|header| header.name.as_ref().is_some_and(|x| x == "Subject"))
                        .ok_or("Error: Subject header not found.")?
                        .value
                        .as_ref()
                        .ok_or("Error: Subject header has no value.")?;

                    let otp = subject
                        .split_whitespace()
                        .find(|str| str.len() == 6 && str.parse::<usize>().is_ok())
                        .ok_or("Error: OTP string not found in the OTP.")?;

                    Ok(Some(otp.to_owned()))
                }
            } else {
                Ok(None)
            }
        } else {
            Err("Error: message list empty.".into())
        }
    }
}
