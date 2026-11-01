//! Payment card numbers: the Luhn check, and the way each card network's
//! numbers begin and how long they are.

use crate::rows::Candidate;
use crate::text;

/// Whether the candidate is a card number: its digits (spaces and dashes
/// dropped) pass the Luhn check and are as long as a network's numbers are
/// and begin as its numbers begin, and it is not a part of a longer number.
pub(crate) fn is_card(candidate: &Candidate<'_>) -> bool {
    let digits: Vec<u8> = candidate
        .secret
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    text::alone(candidate.text, candidate.start, candidate.end)
        && !text::in_longer_number(candidate.text, candidate.start, candidate.end)
        && is_network(&digits)
        && luhn(&digits)
}

/// The Luhn check: from the right, double every second digit, subtract nine
/// from a result over nine, and the sum is a multiple of ten.
fn luhn(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(place, &digit)| {
            let digit = u32::from(digit);
            if place % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                digit
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// The first `count` digits as a number.
fn leading(digits: &[u8], count: usize) -> u32 {
    digits
        .iter()
        .take(count)
        .fold(0, |number, &digit| number * 10 + u32::from(digit))
}

/// Whether the digits are the length and the start of a number of a card
/// network: Visa, Mastercard, American Express, Discover, Diners Club, JCB
/// and UnionPay.
fn is_network(digits: &[u8]) -> bool {
    let length = digits.len();
    let long = (16..=19).contains(&length);
    let (two, three, four, six) = (
        leading(digits, 2),
        leading(digits, 3),
        leading(digits, 4),
        leading(digits, 6),
    );
    let visa = matches!(length, 13 | 16 | 19) && leading(digits, 1) == 4;
    let mastercard = length == 16 && ((51..=55).contains(&two) || (2221..=2720).contains(&four));
    let amex = length == 15 && matches!(two, 34 | 37);
    let discover = long
        && (four == 6011
            || (644..=649).contains(&three)
            || two == 65
            || (622_126..=622_925).contains(&six));
    let diners = length == 14 && ((300..=305).contains(&three) || matches!(two, 36 | 38 | 39));
    let jcb = long && (3528..=3589).contains(&four);
    let unionpay = long && two == 62;
    visa || mastercard || amex || discover || diners || jcb || unionpay
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_the_published_test_numbers_and_refuses_a_changed_digit() {
        let digits = |text: &str| text.bytes().map(|b| b - b'0').collect::<Vec<_>>();
        assert!(luhn(&digits("4111111111111111")));
        assert!(luhn(&digits("5555555555554444")));
        assert!(luhn(&digits("378282246310005")));
        assert!(!luhn(&digits("4111111111111112")));
    }
}
