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

pub fn read_u64(bytes: &[u8]) -> (u64, &[u8]) {
    let mut num = 0;
    let mut i = 0;
    let n = bytes.len();

    while i < n {
        num |= (bytes[i] & 0b01111111) as u64;
        num <<= 7;

        if num & 0b10000000 == 0b10000000 {
            break;
        }

        i += 1;
    }

    if i == n {
        (num, &[])
    } else {
        (num, &bytes[i..])
    }
}

pub fn write_u64(mut num: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1);

    while num > 0 {
        let byte = (num & 0b01111111) as u8;

        num >>= 7;

        if num > 0 {
            buf.push(byte | 0b10000000);
        } else {
            buf.push(byte);
        }
    }

    buf
}

#[test]
fn test() {
    assert_eq!(read_u64(&write_u64(0)).0, 0);
    assert_eq!(read_u64(&write_u64(123)).0, 123);

    assert_eq!(read_u64(&write_u64(u16::MAX as u64)).0, u16::MAX as u64);
    assert_eq!(read_u64(&write_u64(u32::MAX as u64)).0, u32::MAX as u64);
    assert_eq!(read_u64(&write_u64(u64::MAX as u64)).0, u64::MAX as u64);
}
