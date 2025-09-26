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

use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use base64::alphabet::URL_SAFE;
use base64::Engine;

const BASE64_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
);

/// Url-safe base64 encoding.
#[inline]
pub fn encode(data: impl AsRef<[u8]>) -> String {
    BASE64_ENGINE.encode(data)
}

/// Url-safe base64 decoding.
#[inline]
pub fn decode(
    data: impl AsRef<[u8]>
) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_ENGINE.decode(data)
}
