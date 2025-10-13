use reqwest::{
    Client, Url,
    header::{HeaderMap, USER_AGENT},
};
use reqwest_cookie_store::{CookieStore, CookieStoreMutex, RawCookie};
use scraper::{Html, Selector};
use std::{
    collections::HashMap,
    path::{self, Path},
    str::FromStr,
    sync::Arc,
};

use crate::erp::{endpoints, responses};
use crate::utils::{ErpCreds, Res, read_session_file, save_session_file};

pub struct Session {
    cookie_store: Arc<CookieStoreMutex>,
    client: Client,
    credentials: ErpCreds,
    /// The security question for this session
    question: Option<String>,
    /// Secret/security question's answer for this session
    answer: Option<String>,
    /// OTP for this session
    email_otp: Option<String>,
    /// Session token
    session_token: Option<String>,
    /// SSO token
    sso_token: Option<String>,
    /// Headers for the post requests
    headers: HeaderMap,
}

fn get_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "timeout",
        "20".parse().expect("Error setting timeout header."),
    );
    headers.insert(
        USER_AGENT,
        "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0"
            .parse()
            .expect("Error setting user-agent header."),
    );

    headers
}

impl Session {
    pub fn new(credentials: ErpCreds, headers: Option<HeaderMap>) -> Session {
        let cookie_store = CookieStoreMutex::new(CookieStore::new());
        let cookie_store = Arc::new(cookie_store);

        Session {
            client: Client::builder()
                .cookie_provider(cookie_store.clone())
                .build()
                .expect("Error building reqwest Client."),
            cookie_store,
            headers: headers.unwrap_or(get_default_headers()),
            credentials,
            question: None,
            answer: None,
            session_token: None,
            sso_token: None,
            email_otp: None,
        }
    }

    /// Checks if the session is alive
    pub async fn is_alive(&self) -> Res<bool> {
        let resp = self.client.get(endpoints::WELCOMEPAGE_URL).send().await?;

        if let Some(len) = resp.content_length() {
            Ok(len == 1034)
        } else {
            Ok(false)
        }
    }

    /// Fetches the session token
    pub async fn get_session_token(&mut self) -> Res<String> {
        if let Some(session_token) = &self.session_token {
            return Ok(session_token.to_owned());
        }

        let homepage = self
            .client
            .get(endpoints::HOMEPAGE_URL)
            .send()
            .await?
            .text()
            .await?;

        let document = Html::parse_document(&homepage);

        let session_token_selector = Selector::parse("#sessionToken")?;
        let mut elements = document.select(&session_token_selector);

        if let Some(elem) = elements.next() {
            let session_token: String = elem
                .attr("value")
                .map(|val| val.into())
                .ok_or(String::from("Error: session token not found."))?;
            self.session_token = session_token.clone().into();

            Ok(session_token)
        } else {
            Err(String::from("Error: Session token selector element not found.").into())
        }
    }

    /// Fetches the secret question given the rollnumber. If the rollnumber is set in the session struct, it is used instead.
    pub async fn get_secret_question(&mut self, roll_number: Option<String>) -> Res<String> {
        let roll_number = if let Some(roll_number) = &self.credentials.roll_number {
            roll_number.clone()
        } else {
            let roll_number = roll_number.ok_or("Error: No roll number found.")?;
            self.credentials.roll_number = roll_number.clone().into();

            roll_number
        };

        let mut form_data = HashMap::new();
        form_data.insert("user_id", roll_number);

        let resp = self
            .client
            .post(endpoints::SECRET_QUESTION_URL)
            .form(&form_data)
            .headers(self.headers.clone())
            .send()
            .await?
            .text()
            .await?;

        if resp == responses::SECRET_QUES_ROLLNO_INVALID {
            Err("Error: Invalid roll number.".into())
        } else {
            self.question = resp.clone().into();

            Ok(resp)
        }
    }

    /// Requests ERP to send an OTP.
    pub async fn request_otp(
        &mut self,
        password: Option<String>,
        answer: Option<String>,
    ) -> Res<()> {
        if self.credentials.password.is_none() {
            let password = password.ok_or("Error: Password not found.")?;
            self.credentials.password = password.clone().into();
        }

        if let Some(answer) = answer {
            self.answer = answer.clone().into();
        } else {
            let answer_map = self
                .credentials
                .answer_map
                .as_ref()
                .ok_or("Error: No security question answers found.")?;

            let question = self
                .question
                .as_ref()
                .ok_or("Error: Security question for this session not found.")?;

            self.answer = answer_map
                .get(question)
                .ok_or("Error: Answer to the security question not found.")?
                .to_owned()
                .into();
        }

        let login_details = self.get_login_details()?;

        let resp = self
            .client
            .post(endpoints::OTP_URL)
            .form(&login_details)
            .headers(self.headers.clone())
            .build()?;

        let resp = self.client.execute(resp).await?;
        let resp: HashMap<String, String> = resp.json().await?;

        if let Some(msg) = resp.get("msg") {
            match msg.as_str() {
                responses::ANSWER_MISMATCH_ERROR => {
                    Err("Incorrect security question answer.".into())
                }
                responses::PASSWORD_MISMATCH_ERROR => Err("Incorrect password.".into()),
                responses::OTP_SENT_MESSAGE => Ok(()),
                _ => Err(format!("Error requesting OTP: {msg}").into()),
            }
        } else {
            Err("Error: Response has no `msg` field.".into())
        }
    }

    /// Logs into ERP for the current session. Returns the ssoToken
    pub async fn signin(&mut self, otp: String) -> Res<String> {
        self.email_otp = Some(otp);
        let login_details = self.get_login_details()?;

        let resp = self
            .client
            .post(endpoints::LOGIN_URL)
            .form(&login_details)
            .headers(self.headers.clone())
            .send()
            .await?;

        let final_url = resp.url().to_owned();

        if resp.text().await?.as_str() == responses::OTP_MISMATCH_ERROR {
            return Err("OTP mismatch".into());
        }

        if let Some(sso_token_pair) = final_url.query_pairs().find(|pair| pair.0 == "ssoToken") {
            let sso_token = sso_token_pair.1.to_string();
            self.sso_token = Some(sso_token.clone());

            Ok(sso_token)
        } else {
            Err("SSO token not found in URL.".into())
        }
    }

    /// Returns a link to log into ERP with credentials
    /// Opens the homepage by default
    pub fn get_login_url(&self, url: Option<&str>) -> Res<String> {
        if let Some(sso_token) = &self.sso_token {
            Ok(format!(
                "{}?ssoToken={sso_token}",
                url.unwrap_or(endpoints::HOMEPAGE_URL)
            ))
        } else {
            Err("Error: Session not logged in.".into())
        }
    }

    /// Saves the session on a file
    pub async fn save_session<P: AsRef<Path>>(&self, file_path: P) -> Res<()> {
        let file_path = path::absolute(file_path)?;

        save_session_file(
            file_path,
            self.session_token.as_deref(),
            self.sso_token.as_deref(),
        )
        .await
    }

    /// Loads a session from a saved session file. This only loads the session token and sso token (if they exist), not the credentials.
    pub async fn read_session<P: AsRef<Path>>(&mut self, file_path: P) -> Res<()> {
        let file_path = path::absolute(file_path)?;

        let (session_token, sso_token) = read_session_file(file_path).await?;
        self.session_token = session_token;
        self.sso_token = sso_token;

        if let Some(sso_token) = &self.sso_token {
            let mut store = self
                .cookie_store
                .lock()
                .map_err(|_| "Error getting cookie store.".to_string())?;

            store.clear();

            let sso_token_cookie = RawCookie::new("ssoToken", sso_token);
            store.insert_raw(&sso_token_cookie, &Url::from_str(endpoints::BASE_URL)?)?;
        }

        Ok(())
    }

    /// Returns the form data for login requests
    fn get_login_details(&self) -> Res<Vec<(&'static str, String)>> {
        let user_id = self
            .credentials
            .roll_number
            .as_ref()
            .ok_or("Error: Roll number not found.")?
            .clone();

        let password = self
            .credentials
            .password
            .as_ref()
            .ok_or("Error: Password not found.")?
            .clone();

        let answer = self
            .answer
            .as_ref()
            .ok_or("Error: Secret question answer not found.")?
            .clone();

        let session_token = self
            .session_token
            .as_ref()
            .ok_or("Error: Session token not found.")?
            .clone();

        Ok(vec![
            ("user_id", user_id),
            ("password", password),
            ("answer", answer),
            // No idea what this is
            ("typeee", "SI".into()),
            (
                "email_otp",
                self.email_otp.clone().unwrap_or("".into()).clone(),
            ),
            ("sessionToken", session_token),
            ("requestedUrl", endpoints::HOMEPAGE_URL.into()),
        ])
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new(
            ErpCreds {
                roll_number: None,
                password: None,
                answer_map: None,
            },
            None,
        )
    }
}
