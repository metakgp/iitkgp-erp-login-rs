pub mod endpoints {
    pub const BASE_URL: &str = r"https://erp.iitkgp.ac.in";
    pub const HOMEPAGE_URL: &str = r"https://erp.iitkgp.ac.in/IIT_ERP3/";
    pub const WELCOMEPAGE_URL: &str = r"https://erp.iitkgp.ac.in/IIT_ERP3/welcome.jsp"; // Only accessible when NOT logged in
    pub const LOGIN_URL: &str = "https://erp.iitkgp.ac.in/SSOAdministration/auth.htm";
    pub const SECRET_QUESTION_URL: &str =
        "https://erp.iitkgp.ac.in/SSOAdministration/getSecurityQues.htm";
    pub const OTP_URL: &str = "https://erp.iitkgp.ac.in/SSOAdministration/getEmilOTP.htm"; // blame ERP for the typo
}

pub(crate) mod responses {
    pub const SECRET_QUES_ROLLNO_INVALID: &str = "FALSE";
    pub const ANSWER_MISMATCH_ERROR: &str =
        "Unable to send OTP due to security question's answare mismatch .";
    pub const PASSWORD_MISMATCH_ERROR: &str = "Unable to send OTP due to password mismatch.";
    pub const OTP_SENT_MESSAGE: &str = "An OTP(valid for a short time) has been sent to your email id registered with ERP, IIT Kharagpur. Please use that OTP for further processing. ";
    pub const OTP_MISMATCH_ERROR: &str = "ERROR:Email OTP mismatch";
}
