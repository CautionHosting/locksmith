//! Inline PIN entry for smartcard recovery only; no PIN reuse or screen clearing.
use keyfork_prompt::{Error, PromptHandler};
use std::io::{self, IsTerminal, Read, Write};

pub(super) const METADATA: &str =
    "[1/3] Decrypt bundle metadata — check threshold and holder certificates";
pub(super) const SHARE: &str = "[2/3] Decrypt your share — unlock this holder's contribution";
pub(super) const SIGN: &str =
    "[3/3] Sign the encrypted submission — authenticate your contribution to the destination";

pub(super) fn validated_pin(
    handler: &mut dyn PromptHandler,
    prompt: &str,
    retries: u8,
    validate: impl Fn(String) -> Result<String, Box<dyn std::error::Error>>,
) -> Result<String, Error> {
    if !io::stdin().is_terminal()
        || !io::stderr().is_terminal()
        || std::env::var("KEYFORK_PROMPT_TYPE").as_deref() == Ok("headless")
    {
        return keyfork_prompt::prompt_validated_passphrase(handler, prompt, retries, validate);
    }
    let mut last_error = String::new();
    for _ in 0..retries {
        match validate(inline_pin(prompt)?) {
            Ok(pin) => return Ok(pin),
            Err(error) => {
                last_error = error.to_string();
                eprintln!("Error validating passphrase: {last_error}");
            }
        }
    }
    Err(Error::Validation(retries, last_error))
}

// rpassword 7.5 raises SIGINT itself on Ctrl-C. Intercept that byte so the raw
// mode guard is dropped before returning cancellation to the caller.
struct PinInput;
impl Read for PinInput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let read = io::stdin().read(&mut bytes[..1])?;
        if read == 1 && bytes[0] == 3 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "PIN entry cancelled",
            ));
        }
        Ok(read)
    }
}
struct RawMode;
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}
fn inline_pin(prompt: &str) -> Result<String, Error> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    crossterm::terminal::enable_raw_mode()?;
    let guard = RawMode;
    let result = rpassword::read_password_with_config(
        rpassword::ConfigBuilder::new()
            .input_reader(PinInput)
            .output_discard()
            .build(),
    );
    drop(guard);
    eprintln!();
    match result {
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Err(Error::CtrlC),
        result => result.map_err(Error::IO),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "driven by tests/card_prompt_pty.py with a controlling terminal"]
    fn inline_pin_terminal_driver() {
        eprintln!("Existing release summary");
        match super::validated_pin(
            &mut keyfork_prompt::Headless::new(),
            "[1/3] Decrypt bundle metadata\nPIN: ",
            3,
            |pin| {
                if pin.len() < 6 {
                    return Err("PIN too short".into());
                }
                Ok(pin)
            },
        ) {
            Ok(pin) => {
                assert_eq!(pin, "654321");
                eprintln!("PIN accepted");
            }
            Err(keyfork_prompt::Error::CtrlC) => eprintln!("Cancelled"),
            Err(keyfork_prompt::Error::Validation(3, _)) => {
                eprintln!("Validation attempts exhausted")
            }
            other => panic!("unexpected PIN result: {other:?}"),
        }
    }
}
