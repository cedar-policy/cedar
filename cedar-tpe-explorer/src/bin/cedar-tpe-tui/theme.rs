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

//! Colors, mapped from the core's semantic styles.

use cedar_tpe_explorer::doc::Style as S;
use ratatui::style::{Color, Modifier, Style};

pub const FG: Color = Color::Rgb(205, 214, 244);
pub const MUTED: Color = Color::Rgb(108, 112, 134);
pub const PINK: Color = Color::Rgb(242, 168, 212);
pub const GREEN: Color = Color::Rgb(166, 227, 161);
pub const TEAL: Color = Color::Rgb(148, 226, 213);
pub const YELLOW: Color = Color::Rgb(249, 226, 175);
pub const RED: Color = Color::Rgb(243, 139, 168);
pub const PEACH: Color = Color::Rgb(250, 179, 135);
pub const SURFACE: Color = Color::Rgb(88, 91, 112);
pub const BLACK: Color = Color::Rgb(17, 17, 27);

pub fn style(s: S) -> Style {
    let fg = match s {
        S::Plain => FG,
        S::Keyword => PINK,
        S::EntityType => GREEN,
        S::Str => GREEN,
        S::Ident => TEAL,
        S::Literal => GREEN,
        S::Comment | S::Muted | S::UnknownWeak => MUTED,
        S::UnknownStrong => YELLOW,
    };
    let st = Style::default().fg(fg);
    if s == S::UnknownStrong {
        st.add_modifier(Modifier::BOLD)
    } else {
        st
    }
}

pub fn muted() -> Style {
    Style::default().fg(MUTED)
}

pub fn fg() -> Style {
    Style::default().fg(FG)
}
