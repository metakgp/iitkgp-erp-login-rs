use std::{
    error::Error,
    io::{self, Write},
};

use iitkgp_erp_login::session::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut rollno = String::new();

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    print!("Enter roll number: ");
    stdout.flush()?;
    stdin.read_line(&mut rollno)?;
    let rollno = rollno.trim().to_string();

    let password = rpassword::prompt_password("Enter password: ")?;

    let mut session = Session::new(rollno.into(), password.into(), None);
    dbg!(session.get_sessiontoken().await?);

    let secret_ques = session.get_secret_question(None).await?;
    let secret_ans = rpassword::prompt_password(format!("{secret_ques}: "))?;

    dbg!(session.request_otp(None, secret_ans).await?);

    let otp = rpassword::prompt_password("Enter OTP: ")?;

    dbg!(session.signin(otp).await?);

    open::that(session.get_login_url(None)?)?;

    Ok(())
}
