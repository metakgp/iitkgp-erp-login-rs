use reqwest::{
    Client,
    header::{HeaderMap, USER_AGENT},
};
use scraper::{Html, Selector};
use std::{
    collections::{HashMap, hash_map::Keys},
    error::Error,
};

use crate::erp::{endpoints, responses};

pub struct Session {
    client: Client,
    /// Roll number
    user_id: Option<String>,
    /// ERP password
    password: Option<String>,
    /// The security question for this session
    question: Option<String>,
    /// Secret/security question's answer
    answer: Option<String>,
    /// Session token
    session_token: Option<String>,
    /// SSO token
    sso_token: Option<String>,
    /// The ERP url/path that is requested/will be redirected to.
    requested_url: Option<String>,
    /// OTP if required
    email_otp: Option<String>,
    /// Headers for the post requests
    headers: HeaderMap,
}

struct ErpCreds {
    /// Student Roll Number
    roll_number: String,
    /// ERP Password
    password: String,
    /// Security Question
    security_questions_answers: HashMap<String, String>,
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
    pub fn new(
        user_id: Option<String>,
        password: Option<String>,
        headers: Option<HeaderMap>,
    ) -> Session {
        Session {
            client: Client::builder()
                .cookie_store(true)
                .build()
                .expect("Error building reqwest Client."),
            headers: headers.unwrap_or(get_default_headers()),
            user_id,
            password,
            question: None,
            answer: None,
            session_token: None,
            sso_token: None,
            requested_url: None,
            email_otp: None,
        }
    }

    /// Checks if the session is alive
    pub async fn is_alive(&self) -> Result<bool, Box<dyn Error>> {
        let resp = self.client.get(endpoints::WELCOMEPAGE_URL).send().await?;

        if let Some(len) = resp.content_length() {
            Ok(len == 1034)
        } else {
            Ok(false)
        }
    }

    /// Fetches the session token
    pub async fn get_sessiontoken(&mut self) -> Result<String, Box<dyn Error>> {
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
    pub async fn get_secret_question(
        &mut self,
        roll_number: Option<String>,
    ) -> Result<String, Box<dyn Error>> {
        let roll_number = roll_number.unwrap_or(
            self.user_id
                .as_ref()
                .expect("Error: Roll number not found.")
                .clone(),
        );
        self.user_id = roll_number.clone().into();

        let mut map = HashMap::new();
        map.insert("user_id", roll_number);

        let resp = self
            .client
            .post(endpoints::SECRET_QUESTION_URL)
            .form(&map)
            .headers(self.headers.clone())
            .send()
            .await?
            .text()
            .await?;

        if resp == responses::SECRET_QUES_ROLLNO_INVALID {
            Err(String::from("Error: Invalid roll number.").into())
        } else {
            self.question = resp.clone().into();

            Ok(resp)
        }
    }

    /// Returns the form data for login requests
    fn get_login_details(&self) -> Result<Vec<(&'static str, String)>, Box<dyn Error>> {
        Ok(vec![
            (
                "user_id",
                self.user_id
                    .as_ref()
                    .ok_or("Error: Roll number not found.")?
                    .clone(),
            ),
            (
                "password",
                self.password
                    .as_ref()
                    .ok_or("Error: Password not found.")?
                    .clone(),
            ),
            (
                "answer",
                self.answer
                    .as_ref()
                    .ok_or("Error: Secret question answer not found.")?
                    .clone(),
            ),
            // No idea what this is
            ("typeee", "SI".into()),
            (
                "email_otp",
                self.email_otp.clone().unwrap_or("".into()).clone(),
            ),
            (
                "sessionToken",
                self.session_token
                    .as_ref()
                    .ok_or("Error: Session token not found.")?
                    .clone(),
            ),
            ("requestedUrl", endpoints::HOMEPAGE_URL.into()),
        ])
    }

    /// Requests ERP to send an OTP.
    pub async fn request_otp(
        &mut self,
        password: Option<String>,
        answer: String,
    ) -> Result<(), Box<dyn Error>> {
        let password = password.unwrap_or(
            self.password
                .as_ref()
                .expect("Error: Password not found.")
                .clone(),
        );
        self.password = password.into();
        self.answer = answer.into();

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
    pub async fn signin(&mut self, otp: String) -> Result<String, Box<dyn Error>> {
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

        match resp.text().await?.as_str() {
            responses::OTP_MISMATCH_ERROR => return Err(format!("OTP mismatch").into()),
            _ => (),
        }

        return if let Some(query) = final_url.query() {
            let mut query_parts = query.split("=");
            query_parts.next();

            if let Some(sso_token) = query_parts.next() {
                let sso_token = sso_token.to_string();
                self.sso_token = Some(sso_token.clone());

                Ok(sso_token)
            } else {
                Err(format!("Error parsing SSO token query.").into())
            }
        } else {
            Err(format!("SSO token not found in URL.").into())
        };
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new(None, None, None)
    }
}
