//! Issue 71: two rows flagged ordinary text. A Discord bot token is found by
//! its own shape (the first part is a user id in base64url, digits when
//! decoded), not by the lengths of three dotted words; and a quoted word that
//! is a label of a locale file, a pagination cursor and a short token are no
//! password. The real tokens and passwords beside them are still found.

mod common;

use common::fill;
use milo_guards_secrets::{find, find_spans, Rule};

/// `text` as unpadded base64url, the way a Discord bot token writes its id.
fn base64url(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(3) {
        let a = u32::from(chunk[0]);
        let b = chunk.get(1).map_or(0, |b| u32::from(*b));
        let c = chunk.get(2).map_or(0, |b| u32::from(*b));
        let bits = (a << 16) | (b << 8) | c;
        let digits = chunk.len() + 1;
        for n in 0..digits {
            let at = ((bits >> (18 - 6 * n)) & 63) as usize;
            out.push(char::from(ALPHABET[at]));
        }
    }
    out
}

/// A bot token made from a user id, with a fake age and signature.
fn token(id: &str) -> String {
    format!("{}.GaBcDe.{}", base64url(id), fill("FakeDiscordTok_-9", 38))
}

fn assert_safe(rows: &[String]) {
    for row in rows {
        assert!(
            find(row).is_safe(),
            "{row:?}\n  got {:?}",
            find(row).findings()
        );
    }
}

/// Every row has exactly one finding, of `rule`, over the text after
/// `secret_at` in the row up to `secret` itself.
fn assert_found(rows: &[(String, String)], rule: Rule) {
    for (text, secret) in rows {
        let spans = find_spans(text);
        assert_eq!(spans.len(), 1, "{text:?}\n  got {spans:?}");
        assert_eq!(spans[0].rule, rule, "{text:?}");
        assert_eq!(&text[spans[0].start..spans[0].end], secret, "{text:?}");
    }
}

#[test]
fn the_encoder_writes_what_the_discord_row_expects() {
    assert_eq!(base64url("123456789012345678"), "MTIzNDU2Nzg5MDEyMzQ1Njc4");
}

#[test]
fn a_dotted_chain_of_identifiers_is_not_a_discord_token() {
    assert_safe(&[
        "const r = NavigationControllerDelegate.handler.processIncomingNavigationRequest(x);"
            .to_string(),
        "Navigation_Controller_Deleg.handler.processIncomingNavigationRequest()".to_string(),
        "OrderProcessingPipelineFactory.builder.createDefaultOrderProcessingPipeline(cfg)"
            .to_string(),
        "ModelViewControllerBinding.target.updateObservedModelViewControllerState".to_string(),
        // The first part decodes to letters, not to an id.
        format!(
            "see {}.GaBcDe.{}",
            base64url("abcdefghijklmnopqr"),
            fill("FakeDiscordTok_-9", 38)
        ),
        // Digits and letters: not an id either.
        format!(
            "x = {}.GaBcDe.{}",
            base64url("12345678901234567x"),
            fill("FakeDiscordTok_-9", 38)
        ),
        // An id that is too short, and one that is too long, are not a user's.
        format!(
            "{}.GaBcDe.{}",
            base64url("1234567890123456"),
            fill("FakeDiscordTok_-9", 38)
        ),
        format!(
            "{}.GaBcDe.{}",
            base64url("1234567890123456789012"),
            fill("FakeDiscordTok_-9", 38)
        ),
    ]);
}

#[test]
fn a_real_discord_bot_token_is_still_found() {
    let ids = [
        "123456789012345678",
        "1234567890123456789",
        "12345678901234567890",
        "987654321098765432",
        "876543210987654321",
        "556677889900112233",
        // An id of seventeen digits, from the first years of the service.
        "12345678901234567",
    ];
    let mut rows = Vec::new();
    for id in ids {
        let secret = token(id);
        rows.push((format!("DISCORD: {secret}"), secret.clone()));
        rows.push((format!("DISCORD_TOKEN={secret}\n"), secret.clone()));
        rows.push((format!("client.login(\"{secret}\")"), secret.clone()));
        rows.push((format!("see {secret} and more"), secret));
    }
    assert_found(&rows, Rule::ApiKey);
}

#[test]
fn a_discord_token_with_a_seven_character_age_is_found() {
    let secret = format!(
        "{}.GaBcDeF.{}",
        base64url("123456789012345678"),
        fill("FakeDiscordTok_-9", 27)
    );
    assert_found(&[(format!("bot: {secret}"), secret)], Rule::ApiKey);
}

#[test]
fn a_quoted_word_of_a_locale_file_is_no_password() {
    assert_safe(&[
        "{ \"password\": \"Contraseña\", \"confirm_password\": \"Confirmar\" }".to_string(),
        "\"forgot_password\": \"Forgot?\"".to_string(),
        "\"forgot_password\": \"Forgot!\"".to_string(),
        "{\"password\": \"Passwort\", \"new_password\": \"Neues\"}".to_string(),
        "{\"password_confirmation\": \"Confirmación\"}".to_string(),
        "{\"secret\": \"Geheimnis\"}".to_string(),
        "  \"reset_password\": \"Réinitialiser\",".to_string(),
        "{\n  \"login\": \"Login\",\n  \"password\": \"Mot de passe\"\n}".to_string(),
    ]);
}

#[test]
fn a_cursor_of_pagination_is_no_token() {
    assert_safe(&[
        "\"next_page_token\": \"CgsIABCDEF12345\"".to_string(),
        "{\"nextPageToken\": \"CgsIABCDEF12345\"}".to_string(),
        "{\"prev_page_token\": \"CgsIABCDEF12345\"}".to_string(),
        "{\"NextToken\": \"AAAAAAAAAAABBBBBBBBBB1234567890\"}".to_string(),
        "\"continuation_token\": \"eyJhIjoxfQ12345\"".to_string(),
        "next_page_token=CgsIABCDEF12345".to_string(),
        "params.next_page_token = \"CgsIABCDEF12345\";".to_string(),
        "pagination_token: Zm9vYmFyMDEyMzQ1".to_string(),
    ]);
}

#[test]
fn a_page_access_token_is_still_a_secret() {
    let facebook = "EAAGm0PX4ZCpsBAKZB7Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1UgZDZD";
    let word = "Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1Ug";
    let rows = [
        format!("PAGE_TOKEN={facebook}"),
        format!("FB_PAGE_TOKEN={facebook}"),
        format!("export FACEBOOK_PAGE_TOKEN=\"{facebook}\""),
        format!("page_token={facebook}"),
        format!("{{\"page_token\": \"{facebook}\"}}"),
        format!("WEBPAGE_TOKEN={word}"),
        format!("homepage_token = \"{word}\""),
    ];
    for row in &rows {
        assert!(!find(row).is_safe(), "{row:?} is a secret");
    }
}

#[test]
fn a_decoy_discord_match_does_not_hide_the_real_token() {
    let rows = [
        // The decoy begins at a glued letter, and the real token is inside it.
        (
            "NMTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1Ug_-q",
            "MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1Ug_-q",
        ),
        (
            "O_MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1Ug_-q",
            "MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1Ug_-q",
        ),
        // The third part of the decoy swallows the id of the real token.
        (
            "see NavigationControllerDelegate.handler.MTIzNDU2Nzg5MDEyMzQ1Njc4OTA.GaBcDe.Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1Ug_-q",
            "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA.GaBcDe.Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1Ug_-q",
        ),
    ];
    let rows: Vec<(String, String)> = rows
        .into_iter()
        .map(|(text, secret)| (text.to_string(), secret.to_string()))
        .collect();
    assert_found(&rows, Rule::ApiKey);
}

#[test]
fn a_separator_before_a_discord_token_is_not_part_of_a_longer_id() {
    // The base64url of an id made of digits holds no `_` or `-`, so one that
    // touches the token ends the run of letters before it, whatever it was.
    let secret = "MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.Xk9fQ2mZ7pLw3RtY8vBn4CsHj6KdEa1Ug_-q";
    let rows: Vec<(String, String)> = [
        "token_",
        "key-",
        "prod_",
        "abc_",
        "my-bot-",
        "secrets/discord-bot-",
        "____",
        "----",
        "--token--",
    ]
    .into_iter()
    .map(|head| (format!("{head}{secret}"), secret.to_string()))
    .collect();
    assert_found(&rows, Rule::ApiKey);
    assert!(
        !find(&format!("secrets/discord-bot-{secret}.txt")).is_safe(),
        "a token in a file name is a secret"
    );
    // Four letters or digits right before the token are still a longer id.
    for head in ["abcd", "x_abcd", "Zm9v1234"] {
        let row = format!("{head}{secret}");
        assert!(
            find_spans(&row).iter().all(|s| s.rule != Rule::ApiKey),
            "{row:?} is the tail of a longer id"
        );
    }
}

#[test]
fn a_short_quoted_token_is_no_token() {
    assert_safe(&[
        "let token = \"abc123\";".to_string(),
        "let token = \"abc1234\";".to_string(),
        "token = 'x9y8z7'".to_string(),
        "api_key = \"k3y123\"".to_string(),
        "{\"token\": \"t0k3n99\"}".to_string(),
    ]);
}

#[test]
fn a_real_password_or_token_beside_those_rows_is_still_found() {
    let long = fill("Fk9Zq2Xw", 32);
    let rows: Vec<(String, String)> = [
        // A quoted password with a digit or a symbol is not a word.
        ("{\"password\": \"Contraseña1\"}", "Contraseña1"),
        ("{\"password\": \"Hunter2!\"}", "Hunter2!"),
        ("{\"password\": \"Correct?Horse\"}", "Correct?Horse"),
        ("{\"password\": \"hunter22\"}", "hunter22"),
        ("{\"confirm_password\": \"Confirmar#7\"}", "Confirmar#7"),
        // Not a Title word: lower case, upper case or several capitals.
        ("{\"password\": \"sunshine\"}", "sunshine"),
        ("{\"password\": \"SUNSHINE\"}", "SUNSHINE"),
        ("{\"password\": \"SunShine\"}", "SunShine"),
        // A word as the value of a name that is not a key of data.
        ("password = \"Sunshine\"", "Sunshine"),
        ("let password = \"Sunshine\";", "Sunshine"),
        ("password: Sunshine1", "Sunshine1"),
        // More than a word, or too long to be a label.
        (
            "{\"password\": \"Supercalifragilisticexpialidocious\"}",
            "Supercalifragilisticexpialidocious",
        ),
        // A quoted token of eight characters, and a long one under any name.
        ("let token = \"abc12345\";", "abc12345"),
        ("{\"token\": \"Xk9fQ2mZ\"}", "Xk9fQ2mZ"),
        ("let api_token = \"Xk9fQ2mZ7p\";", "Xk9fQ2mZ7p"),
        // A secret short value under a word that is not a token's.
        ("password = \"abc123\"", "abc123"),
        ("let secret = \"abc123\";", "abc123"),
    ]
    .into_iter()
    .map(|(text, secret)| (text.to_string(), secret.to_string()))
    .chain([
        (format!("{{\"token\": \"{long}\"}}"), long.clone()),
        (format!("let token = \"{long}\";"), long.clone()),
        (format!("\"next_token_secret\": \"{long}\""), long.clone()),
        (format!("{{\"page_secret\": \"{long}\"}}"), long.clone()),
        (format!("{{\"api_key\": \"{long}\"}}"), long),
    ])
    .collect();
    assert_found(&rows, Rule::GenericSecret);
}
