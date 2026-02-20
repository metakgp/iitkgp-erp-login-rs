use std::time::Duration;

use tokio::time::sleep;

use crate::utils::Res;

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

pub fn is_otp(str: &str) -> bool {
    str.len() == 6 && str.parse::<usize>().is_ok()
}

pub fn get_otp_from_sub(subject: &str) -> Option<String> {
    subject
        .split_whitespace()
        .find(|str| is_otp(str))
        .map(|str| str.to_owned())
}
