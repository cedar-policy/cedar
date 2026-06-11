/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::CedarExitCode;

pub fn license() -> CedarExitCode {
    println!(
        "Cedar is licensed under the Apache License, Version 2.0.\n\
         See https://www.apache.org/licenses/LICENSE-2.0 for the full text.\n\n\
         Third-party dependency licenses follow:\n"
    );
    print!("{}", include_str!("../../../THIRD_PARTY_LICENSES.txt"));
    CedarExitCode::Success
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn license_succeeds() {
        assert_eq!(license(), CedarExitCode::Success);
    }
}
