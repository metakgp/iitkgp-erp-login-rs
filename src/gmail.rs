use google_gmail1::{
    Gmail,
    api::Scope,
    hyper_rustls::{self, HttpsConnector},
    hyper_util::{self, client::legacy::connect::HttpConnector},
    yup_oauth2::{self, InstalledFlowAuthenticator, InstalledFlowReturnMethod},
};

use crate::{
    erp,
    otp::{OTPRetriever, get_otp_from_sub},
    utils::Res,
};

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

impl OTPRetriever for GmailAPIObserver {
    async fn get_otp(&self, after_timestamp: i64) -> Res<Option<String>> {
        let (_, msgs) = self
            .client
            .users()
            .messages_list("me")
            .q(format!(
                "from:{} subject:\"{}\"",
                erp::email::ERP_EMAIL,
                erp::email::ERP_OTP_SUBJECT_PREFIX
            )
            .as_ref())
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

                    let otp =
                        get_otp_from_sub(subject).ok_or("Error: No OTP found in the subject.")?;

                    Ok(Some(otp))
                }
            } else {
                Ok(None)
            }
        } else {
            Err("Error: message list empty.".into())
        }
    }
}
