// SPDX-License-Identifier: GPL-3.0-or-later
//
// libflowerpot
// Copyright (C) 2025  Nikita Podvirnyi <krypt0nn@vk.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

/// Read variable sized number from the provided bytes slice, return read number
/// and the slice's tail which doesn't encode the returned number.
///
/// Return `None` if the encoded number is invalid (too large) or provided bytes
/// slice is empty.
pub fn read_u64(bytes: &[u8]) -> (Option<u64>, &[u8]) {
    let mut num = 0;
    let mut i = 0;

    let n = bytes.len();

    if n == 0 {
        return (None, &[]);
    }

    // Locate the end of the varint (no extension bit).
    while i < n {
        if bytes[i] & 0b10000000 == 0 {
            break;
        }

        i += 1;

        // To encode up to 64 bits we need ceil(64 / 7) = 10 bytes.
        // If there's more than that then the number is too large, so reject it.
        if i >= 10 {
            return (None, &[]);
        }
    }

    // Check that the last part of the number is valid and that we've found it.
    if i >= n || bytes[i] & 0b10000000 != 0 {
        return (None, &[]);
    }

    // Decode the number by going backward to preserve the encoded order.
    loop {
        num |= (bytes[i] & 0b01111111) as u64;

        if i == 0 {
            break;
        }

        num <<= 7;
        i -= 1;
    }

    if i >= n {
        (Some(num), &[])
    } else {
        (Some(num), &bytes[i..])
    }
}

/// Encode provided number into variably sized bytes vector. Numbers under 128
/// are encoded in one single byte.
pub fn write_u64(mut num: u64) -> Vec<u8> {
    // Special case.
    if num == 0 {
        return vec![0];
    }

    let mut buf = Vec::with_capacity(1);

    while num > 0 {
        // Take 7 bits from the number.
        let byte = (num & 0b01111111) as u8;

        num >>= 7;

        // If the number is not done yet.
        if num > 0 {
            // Add extension bit if we have more parts of the number.
            buf.push(byte | 0b10000000);
        }

        // Otherwise don't add extension bit, marking varint as finished.
        else {
            buf.push(byte);
        }
    }

    buf
}

#[test]
fn test() {
    dbg!(write_u64(123));
    dbg!(write_u64(u16::MAX as u64));

    assert_eq!(read_u64(&write_u64(0)).0, Some(0));
    assert_eq!(read_u64(&write_u64(123)).0, Some(123));

    assert_eq!(read_u64(&write_u64(u16::MAX as u64)).0, Some(u16::MAX as u64));
    assert_eq!(read_u64(&write_u64(u32::MAX as u64)).0, Some(u32::MAX as u64));
    assert_eq!(read_u64(&write_u64(u64::MAX)).0, Some(u64::MAX));

    // Empty slice.
    assert_eq!(read_u64(&[]), (None, &[] as &[u8]));

    // Invalid number (last part must not contain extension bit).
    assert_eq!(read_u64(&[0xFF, 0xFF]), (None, &[] as &[u8]));

    // Too large number.
    assert_eq!(read_u64(&[0xFF; 32]), (None, &[] as &[u8]));
}
