use std::{
    error::Error,
    io::{self, Write},
    path,
    str::FromStr,
};

use iitkgp_erp_login::{ErpCreds, Session, gmail::GmailAPIObserver, otp::OTPRetriever};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let hub = GmailAPIObserver::new().await?;

    let session_file_path = path::PathBuf::from_str(".session")?;
    let creds_file_path = path::PathBuf::from_str("erpcreds.json")?;

    if session_file_path.exists() {
        println!(
            "Found session file {}. Checking session.",
            session_file_path.display()
        );

        let mut session = Session::default();
        session.read_session(&session_file_path).await?;

        let is_alive = session.is_alive().await?;
        println!("Session alive: {}", session.is_alive().await?);

        if is_alive {
            open::that(session.get_login_url(None)?)?;
            return Ok(());
        }
    }

    let (creds, creds_loaded) = if creds_file_path.exists() {
        println!("Reading credentials file {}.", creds_file_path.display());

        (ErpCreds::from_file(creds_file_path)?, true)
    } else {
        let mut rollno = String::new();

        let stdin = io::stdin();
        let mut stdout = io::stdout();

        print!("Enter roll number: ");
        stdout.flush()?;
        stdin.read_line(&mut rollno)?;
        let rollno = rollno.trim().to_string();

        let password = rpassword::prompt_password("Enter password: ")?;

        (
            ErpCreds {
                roll_number: rollno.into(),
                password: password.into(),
                answer_map: None,
            },
            false,
        )
    };

    let mut session = Session::new(creds, None);
    dbg!(session.get_session_token().await?);

    let secret_ques = session.get_secret_question(None).await?;
    let secret_ans = if !creds_loaded {
        Some(rpassword::prompt_password(format!("{secret_ques}: "))?)
    } else {
        None
    };

    let after_timestamp = session.request_otp(None, secret_ans).await?;

    let otp = hub.wait_for_otp(after_timestamp, 5).await?;
    let otp = if let Some(otp) = otp {
        println!("Obtained OTP from the email.");
        otp
    } else {
        rpassword::prompt_password("Email OTP could not be retrieved. Enter manually: ")?
    };

    dbg!(session.signin(otp).await?);

    session.save_session(session_file_path).await?;
    open::that(session.get_login_url(None)?)?;

    Ok(())
}
