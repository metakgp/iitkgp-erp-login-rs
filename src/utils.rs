use std::{
    collections::HashMap,
    error::Error,
    path::{Path, PathBuf},
};

use tokio::fs;

use serde::{Deserialize, Serialize};
pub type Res<T> = Result<T, Box<dyn Error>>;

/// Saves the session token and SSO token on a file
pub async fn save_session_file(
    file_path: PathBuf,
    session_token: Option<&str>,
    sso_token: Option<&str>,
) -> Res<()> {
    fs::write(
        file_path,
        format!(
            "{}\n{}\n",
            session_token.unwrap_or_default(),
            sso_token.unwrap_or_default()
        ),
    )
    .await?;

    Ok(())
}

/// Reads a session file and returns the session token and SSO token (if they exist)
pub async fn read_session_file(file_path: PathBuf) -> Res<(Option<String>, Option<String>)> {
    let file_contents = fs::read_to_string(file_path).await?;
    let mut lines = file_contents.lines();

    Ok((
        lines.next().map(str::to_string),
        lines.next().map(str::to_string),
    ))
}

#[derive(Debug, Serialize, Deserialize)]
/// Used to store ERP credentials in a file (typically erpcreds.json)
pub struct ErpCreds {
    /// Student Roll Number
    pub roll_number: Option<String>,
    /// ERP Password
    pub password: Option<String>,
    /// Security Question
    pub answer_map: Option<HashMap<String, String>>,
}

impl ErpCreds {
    pub fn from_file<P: AsRef<Path>>(file_path: P) -> Res<Self> {
        let file_reader = std::fs::File::open(file_path)?;

        Ok(serde_json::from_reader(file_reader)?)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, file_path: P) -> Res<()> {
        let file_writer = std::fs::File::create(file_path)?;
        Ok(serde_json::to_writer(file_writer, self)?)
    }
}
