#!/bin/bash
# Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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


# This script ensures that exceptions to the clippy lints have explanations in the comments

total_checked_panics=0
total_panics=0
failed=0

crates=("cedar-policy-core")
panic_markers=("unwrap_used expect_used fallible_impl_from unreachable")

for crate in ${crates[@]}; do
    for panic_marker in ${panic_markers[@]}; do
        while read -r filename linenum ; do 
            msg_line=$(($linenum - 1))
            if sed "$msg_line!d" $filename | grep 'PANIC SAFETY' > /dev/null ; then 
                total_checked_panics=$(($total_checked_panics + 1))
                total_panics=$(($total_panics + 1))
            else
                echo "Unchecked panic at $filename:$linenum"
                total_panics=$(($total_panics + 1))
                failed=1
            fi
        done < <(grep -n -r "allow(clippy::$panic_marker)" ./"$crate" | awk -F ':' '{ print $1 " " $2 }')
    done
done

echo $total_checked_panics

exit $failed
