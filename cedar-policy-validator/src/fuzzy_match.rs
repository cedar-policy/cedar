/*
 * Copyright 2022-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

/// Fuzzy string matching using the Levenshtein distance algorithm
pub fn fuzzy_search(key: &str, lst: &[impl AsRef<str>]) -> Option<String> {
    if key.is_empty() || lst.is_empty() {
        None
    } else {
        let t = lst.iter().fold((std::usize::MAX, ""), |acc, word| {
            let e = levenshtein_distance(key, word.as_ref());
            if e < acc.0 {
                (e, word.as_ref())
            } else {
                acc
            }
        });
        Some(t.1.to_owned())
    }
}
pub fn levenshtein_distance(word1: &str, word2: &str) -> usize {
    let w1 = word1.chars().collect::<Vec<_>>();
    let w2 = word2.chars().collect::<Vec<_>>();
    let word1_length = w1.len() + 1;
    let word2_length = w2.len() + 1;
    let mut matrix = vec![vec![0; word1_length]; word2_length];

    // The access at 0 is safe because `word2_length` is at least 1.
    // The access at `i` is safe because it stops before `word1_length`.
    // PANIC SAFETY: See above.
    #[allow(clippy::indexing_slicing)]
    for i in 1..word1_length {
        matrix[0][i] = i;
    }
    // PANIC SAFETY: Similar to above, but fixing the column index instead.
    #[allow(clippy::indexing_slicing)]
    #[allow(clippy::needless_range_loop)]
    for j in 1..word2_length {
        matrix[j][0] = j;
    }

    // `i` and `j` start at 1, so the accesses at `i - 1` and `j - 1` are safe.
    // `i` and `j` stop before the length of the array in their respective
    // dimensions, so accesses at `i` and `j` are safe.
    // PANIC SAFETY: See above.
    #[allow(clippy::indexing_slicing)]
    for j in 1..word2_length {
        for i in 1..word1_length {
            let x: usize = if w1[i - 1] == w2[j - 1] {
                matrix[j - 1][i - 1]
            } else {
                1 + std::cmp::min(
                    std::cmp::min(matrix[j][i - 1], matrix[j - 1][i]),
                    matrix[j - 1][i - 1],
                )
            };
            matrix[j][i] = x;
        }
    }
    // PANIC SAFETY: Accesses at one less than length in both dimensions. The length in both dimensions is non-zero.
    #[allow(clippy::indexing_slicing)]
    matrix[word2_length - 1][word1_length - 1]
}

#[cfg(test)]
pub mod test {
    use super::*;

    ///the key differs by 1 letter from a word in words
    #[test]
    fn test_match1() {
        let word1 = "user::Alice";
        let words = vec!["User::Alice", "user::alice", "user", "alice"];
        let x = fuzzy_search(word1, &words);
        assert_eq!(x, Some("User::Alice".to_owned()));
    }

    ///the key differs by 1 letter from a word in words
    #[test]
    fn test_match2() {
        let word1 = "princpal";
        let words = vec![
            "principal",
            "Principal",
            "principality",
            "prince",
            "principle",
        ];
        let x = fuzzy_search(word1, &words);
        assert_eq!(x, Some("principal".to_owned()));
    }

    ///the word1 differs by two letters from a word in words
    #[test]
    fn test_match3() {
        let word1 = "prncpal";
        let words = vec![
            "principal",
            "Principal",
            "principality",
            "prince",
            "principle",
        ];
        let x = fuzzy_search(word1, &words);
        assert_eq!(x, Some("principal".to_owned()));
    }

    ///the word1 contains special characters like "
    #[test]
    fn test_match4() {
        let word1 = "user::\"Alice\"";
        let words = vec!["User::\"Alice\"", "user::\"alice\"", "user", "alice"];
        let x = fuzzy_search(word1, &words);
        assert_eq!(x, Some("User::\"Alice\"".to_owned()));
    }

    ///the word1 is the empty string
    #[test]
    fn test_match5() {
        let word1 = "";
        let words = vec!["User::\"Alice\"", "user::\"alice\"", "user", "alice"];
        let x = fuzzy_search(word1, &words);
        assert_eq!(x, None); //Some("user".to_owned()));
    }

    ///the words list contains duplicates
    #[test]
    fn test_match6() {
        let word1 = "prncpal";
        let words = vec![
            "principal",
            "Principal",
            "principality",
            "principal",
            "prince",
            "principle",
            "principal",
        ];
        let x = fuzzy_search(word1, &words);
        assert_eq!(x, Some("principal".to_owned()));
    }

    ///the word1 differs by a word in words only due to a special character (eg: ' instead of ")
    #[test]
    fn test_match7() {
        let word1 = "User::\"Alice\"";
        let words = vec!["User::\'Alice\'", "user::\"alice\"", "user", "alice"];
        let x = fuzzy_search(word1, &words);
        assert_eq!(x, Some("User::\'Alice\'".to_owned()));
    }

    #[test]
    fn test_match_empty() {
        let word1 = "user::Alice";
        let words: Vec<&str> = Vec::new();
        let x = fuzzy_search(word1, &words);
        assert_eq!(x, None);
    }
}
