#!/bin/bash
# Copyright Cedar Contributors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script ensures that exceptions to the clippy lints have explanations in
# the comments. It assumes that clippy is properly configured to forbid the
# lints listed in `panic_markers` and that clippy is being run regularly.
# Clippy is automatically run against PRs on GitHub.  Clippy lints are
# controlled for all of our crates by `./.cargo/config.toml`.


# Check that panics are prefixed with a line that has "PANIC SAFETY" in it
total_panics=0
failed=0

crates=($(cargo metadata --no-deps --format-version 1 | jq -r '.packages | map(.name) | join(" ")'))
panic_markers=("unwrap_used expect_used fallible_impl_from unreachable indexing_slicing panic")

for crate in ${crates[@]}; do
    crate_panics=0
    for panic_marker in ${panic_markers[@]}; do
        while read -r filename linenum ; do
            msg_line=$(($linenum - 1))
            if sed "$msg_line!d" $filename | grep 'PANIC SAFETY' > /dev/null ; then
                crate_panics=$(($crate_panics + 1))
            else
                echo "Unchecked panic at $filename:$linenum"
                crate_panics=$(($crate_panics + 1))
                failed=1
            fi
        done < <(grep -n -r "allow(clippy::$panic_marker)" ./"$crate" | awk -F ':' '{ print $1 " " $2 }')
    done
    echo "$crate: $crate_panics"
    total_panics=$(($total_panics + $crate_panics))
done

echo "Total Panics: $total_panics"

if ((failed > 0))
then
    exit $failed
else
    # Check for "should_panic"s without "expected = ..."
    num_should_panic=$(grep -inr --include \*.rs should_panic | wc -l)
    echo "num 'should_panic's " $num_should_panic
    num_should_panic_lparen=$(grep -inr --include \*.rs should_panic\( | wc -l)
    echo "num 'should_panic('s " $num_should_panic_lparen
    if ((num_should_panic == num_should_panic_lparen))
    then
        exit 0
    else
        echo "failed should_panic( test"
        echo "every 'should_panic' should also be a 'should_panic('"
        exit 1
    fi
fi
