use std::{error::Error, path::PathBuf};

use tokio::fs;

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
