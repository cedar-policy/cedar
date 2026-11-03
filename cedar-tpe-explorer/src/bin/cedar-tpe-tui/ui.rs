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

//! Drawing.

use cedar_tpe_explorer::analysis::Need;
use cedar_tpe_explorer::doc::{self, Gutter, PolicyMark};
use cedar_tpe_explorer::edit::{self, EditState};
use cedar_tpe_explorer::eval::{decision_str, Status};
use cedar_tpe_explorer::SlotId;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use cedar_policy_core::authorizer::Decision;

use crate::app::{App, FlashKind, Focus, Mode, SuggestTarget, Tab};
use crate::theme::{self, *};

pub fn draw(f: &mut Frame<'_>, app: &mut App) {
    let [top, mid, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(6),
    ])
    .areas(f.area());
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)])
            .spacing(1)
            .areas(mid);
    draw_status(f, app, top);
    draw_facts(f, app, left);
    draw_right(f, app, right);
    draw_bottom(f, app, bottom);
    match &app.mode {
        Mode::Suggest(_) => draw_suggest(f, app, mid),
        Mode::Help => draw_help(f, mid),
        _ => {}
    }
}

fn draw_status(f: &mut Frame<'_>, app: &App, area: Rect) {
    let mut spans: Vec<Span<'_>> = Vec::new();
    match &app.session.eval {
        Err(e) => {
            spans.push(Span::styled(
                " ERROR ",
                Style::default()
                    .bg(RED)
                    .fg(BLACK)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(format!(" {e}"), Style::default().fg(RED)));
        }
        Ok(eval) => match eval.decision {
            None => {
                spans.push(Span::styled(
                    " UNKNOWN ",
                    Style::default()
                        .bg(YELLOW)
                        .fg(BLACK)
                        .add_modifier(Modifier::BOLD),
                ));
                spans.push(Span::styled(
                    format!(
                        " {} residual · {} satisfied · {} not · {} error",
                        eval.count(Status::Residual),
                        eval.count(Status::True),
                        eval.count(Status::False),
                        eval.count(Status::Error)
                    ),
                    theme::fg(),
                ));
            }
            Some(d) => {
                let color = if d == Decision::Allow { GREEN } else { RED };
                spans.push(Span::styled(
                    format!(" {} ", decision_str(d)),
                    Style::default()
                        .bg(color)
                        .fg(BLACK)
                        .add_modifier(Modifier::BOLD),
                ));
                let reasons: Vec<String> = eval.reasons().iter().map(|p| p.title()).collect();
                let reasons = if reasons.is_empty() {
                    "no permit applies".to_string()
                } else {
                    reasons.join(", ")
                };
                spans.push(Span::styled(
                    format!(" {reasons}"),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ));
                let n = eval.irrelevant_count();
                if n > 0 {
                    spans.push(Span::styled(
                        format!(
                            " · {n} {} no longer matter",
                            if n == 1 { "policy" } else { "policies" }
                        ),
                        muted(),
                    ));
                }
            }
        },
    }
    if let Some(fl) = &app.flash {
        let st = match fl.kind {
            FlashKind::Info => muted(),
            FlashKind::Error => Style::default().fg(RED),
        };
        spans.push(Span::styled(format!("  {}", fl.text), st));
    }
    spans.push(Span::styled("   ? help  q quit", muted()));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn pane_block(title: Vec<Span<'static>>, focused: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused { TEAL } else { SURFACE }))
        .title(Line::from(title))
}

fn gutter_spans(g: Gutter, selected_policy: bool) -> Vec<Span<'static>> {
    match g {
        Gutter::None => vec![Span::raw("  ")],
        Gutter::Bare => vec![],
        Gutter::Needed => vec![Span::styled("◀ ", Style::default().fg(YELLOW))],
        Gutter::Policy(m) => {
            let color = match m {
                PolicyMark::Residual => MUTED,
                PolicyMark::Satisfied => TEAL,
                PolicyMark::NotSatisfied | PolicyMark::Error => MUTED,
            };
            let st = if selected_policy {
                Style::default().bg(SURFACE).fg(FG)
            } else {
                Style::default().fg(color)
            };
            vec![Span::styled(m.symbol(), st), Span::raw(" ")]
        }
    }
}

/// Is `slot` related to (inside, or containing) `other`?
fn related(a: &SlotId, b: &SlotId) -> bool {
    a.contains(b) || b.contains(a)
}

fn scroll_into_view(scroll: &mut usize, line: Option<usize>, height: usize) {
    if let Some(l) = line {
        if l < *scroll {
            *scroll = l.saturating_sub(1);
        } else if l >= *scroll + height {
            *scroll = l + 1 - height;
        }
    }
}

fn draw_facts(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::Facts;
    let title_st = if focused {
        Style::default().fg(TEAL)
    } else {
        muted()
    };
    let block = pane_block(vec![Span::styled(" Facts ", title_st)], focused);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let eval = app.session.eval.as_ref().ok();
    let lines = doc::render_facts(&app.session.project, &app.session.facts, eval);
    let editing = matches!(app.mode, Mode::Edit(_));
    let policy_needs: Vec<Need> = match (app.focus, eval, &app.sel_policy) {
        (Focus::Residuals, Some(e), Some(id)) => {
            e.policy(id).map(|p| p.needs.clone()).unwrap_or_default()
        }
        _ => vec![],
    };
    let mut sel_line = None;
    let out: Vec<Line<'_>> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let mut spans = gutter_spans(l.gutter, false);
            for s in &l.spans {
                let mut st = theme::style(s.style);
                if let Some(slot) = &s.slot {
                    let selected = focused && app.sel_slot.as_ref() == Some(slot);
                    if selected {
                        sel_line.get_or_insert(i);
                    }
                    if focused && app.changed.contains(slot) && !(selected && editing) {
                        st = st.bg(GREEN).fg(BLACK);
                    } else if selected {
                        st = if s.style == doc::Style::UnknownStrong {
                            st.bg(YELLOW).fg(BLACK)
                        } else if editing {
                            st.bg(TEAL).fg(BLACK)
                        } else {
                            st.bg(SURFACE)
                        };
                    }
                    if policy_needs.iter().any(|n| related(&n.slot, slot)) {
                        st = st.add_modifier(Modifier::UNDERLINED);
                    }
                }
                spans.push(Span::styled(s.text.clone(), st));
            }
            Line::from(spans)
        })
        .collect();
    scroll_into_view(&mut app.facts_scroll, sel_line, inner.height as usize);
    f.render_widget(
        Paragraph::new(out).scroll((u16_of(app.facts_scroll), 0)),
        inner,
    );
}

fn draw_right(f: &mut Frame<'_>, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::Residuals;
    let mut title = Vec::new();
    for t in Tab::ALL {
        let st = if t == app.tab {
            Style::default()
                .bg(TEAL)
                .fg(BLACK)
                .add_modifier(Modifier::BOLD)
        } else {
            muted()
        };
        title.push(Span::styled(format!(" {} ", t.title()), st));
        title.push(Span::raw("  "));
    }
    title.push(Span::styled("v cycle ", muted()));
    let block = pane_block(title, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let width = (inner.width as usize).saturating_sub(1);
    let (lines, sel_line): (Vec<Line<'_>>, Option<usize>) = match app.tab {
        Tab::Policies => (
            to_lines(doc::highlight_source(&app.session.project.policies_src)),
            None,
        ),
        Tab::Schema => (
            to_lines(doc::highlight_source(&app.session.project.schema_src)),
            None,
        ),
        Tab::Residuals => match &app.session.eval {
            Err(e) => (
                vec![Line::styled(e.clone(), Style::default().fg(RED))],
                None,
            ),
            Ok(eval) => {
                let sel_slot = match app.focus {
                    Focus::Facts => app.sel_slot.clone(),
                    Focus::Residuals => None,
                };
                let mut sel_line = None;
                let env = cedar_tpe_explorer::analysis::TypeEnv::new(
                    &app.session.project,
                    &app.session.facts,
                );
                let lines = doc::render_residuals(env, eval, width)
                    .into_iter()
                    .enumerate()
                    .map(|(i, l)| {
                        let selected = focused && l.policy.is_some() && l.policy == app.sel_policy;
                        if selected {
                            sel_line = Some(i);
                        }
                        let mut spans = gutter_spans(l.gutter, selected);
                        for s in &l.spans {
                            let mut st = if l.dim {
                                muted()
                            } else {
                                theme::style(s.style)
                            };
                            if let Some(sel) = &sel_slot {
                                if s.marks.iter().any(|m| related(m, sel)) {
                                    st = st.add_modifier(Modifier::UNDERLINED);
                                }
                            }
                            spans.push(Span::styled(s.text.clone(), st));
                        }
                        Line::from(spans)
                    })
                    .collect();
                (lines, sel_line)
            }
        },
    };
    if app.tab == Tab::Residuals {
        scroll_into_view(&mut app.right_scroll, sel_line, inner.height as usize);
    }
    let max = lines.len().saturating_sub(1);
    app.right_scroll = app.right_scroll.min(max);
    f.render_widget(
        Paragraph::new(lines).scroll((u16_of(app.right_scroll), 0)),
        inner,
    );
}

fn to_lines(lines: Vec<doc::Line>) -> Vec<Line<'static>> {
    lines
        .into_iter()
        .map(|l| {
            Line::from(
                l.spans
                    .into_iter()
                    .map(|s| Span::styled(s.text, theme::style(s.style)))
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

fn need_style(msg: &str) -> Style {
    if msg.starts_with("needed") || msg.starts_with("blocked") {
        Style::default().fg(YELLOW)
    } else {
        muted()
    }
}

fn draw_bottom(f: &mut Frame<'_>, app: &App, area: Rect) {
    let title = match (app.focus, &app.sel_slot) {
        (Focus::Facts, Some(s)) => s.label(),
        _ => "nothing selected".into(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(FG))
        .title(Span::styled(format!(" {title} "), theme::fg()));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let eval = app.session.eval.as_ref().ok();
    let mut lines: Vec<Line<'_>> = Vec::new();
    match &app.mode {
        Mode::Edit(e) => {
            let mut spans = Vec::new();
            for (i, s) in EditState::ALL.iter().enumerate() {
                let text = format!("{}:{}", i + 1, s.label());
                let st = if *s == e.state {
                    Style::default().bg(TEAL).fg(BLACK)
                } else if e.allowed.contains(s) {
                    muted()
                } else {
                    muted().add_modifier(Modifier::DIM | Modifier::CROSSED_OUT)
                };
                spans.push(Span::styled(text, st));
                spans.push(Span::raw("   "));
            }
            lines.push(Line::from(spans));
            if e.state == EditState::Value {
                let buf_style = if e.fresh {
                    Style::default().bg(SURFACE).fg(FG)
                } else {
                    theme::fg()
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{} ", edit::prompt(&e.slot)), muted()),
                    Span::styled(e.buf.clone(), buf_style),
                    Span::styled(" ", Style::default().bg(TEAL)),
                ]));
            } else {
                lines.push(Line::styled(
                    format!("⏎ to mark {} as {}", e.slot.label(), e.state.label()),
                    muted(),
                ));
            }
            match (&e.error, eval) {
                (Some(err), _) => lines.push(Line::styled(err.clone(), Style::default().fg(RED))),
                (None, Some(ev)) => {
                    let msg = ev.describe_slot_need(&e.slot);
                    lines.push(Line::styled(msg.clone(), need_style(&msg)));
                }
                _ => {}
            }
        }
        _ => {
            let help = match app.focus {
                Focus::Facts => "⏎ edit   1-4 state   s suggest   ↔ pane   ↑↓ move   v policy tab   u undo   r redo",
                Focus::Residuals => "⏎ suggest   ↔ pane   ↑↓ move   v policy tab   u undo   r redo",
            };
            lines.push(Line::styled(help, muted()));
            if let Some(ev) = eval {
                let msg = match (app.focus, &app.sel_slot) {
                    (Focus::Facts, Some(s)) => ev.describe_slot_need(s),
                    _ => ev.describe_settled(),
                };
                lines.push(Line::styled(msg.clone(), need_style(&msg)));
                for w in &ev.warnings {
                    lines.push(Line::styled(
                        format!("warning: {w}"),
                        Style::default().fg(PEACH),
                    ));
                }
            }
        }
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn popup(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width.saturating_sub(4));
    let h = height.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

fn draw_suggest(f: &mut Frame<'_>, app: &App, area: Rect) {
    let Mode::Suggest(s) = &app.mode else {
        return;
    };
    let bold = |c| Style::default().fg(c).add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line<'_>> = Vec::new();
    match &s.target {
        SuggestTarget::Slot(slot) => {
            lines.push(Line::from(vec![
                Span::styled("assignments for ", muted()),
                Span::styled(slot.label(), bold(TEAL)),
            ]));
            lines.push(Line::styled("each sets this field alone", muted()));
        }
        SuggestTarget::Policy(id) => {
            lines.push(Line::from(vec![
                Span::styled("bindings that settle ", muted()),
                Span::styled(format!("«{id}»"), bold(TEAL)),
            ]));
            lines.push(Line::styled("fewest fields that settle it", muted()));
        }
    }
    lines.push(Line::raw(""));
    if let Some(m) = &s.message {
        lines.push(Line::styled(m.clone(), Style::default().fg(YELLOW)));
    }
    for (i, sug) in s.items.iter().enumerate() {
        let selected = i == s.sel;
        for (j, a) in sug.assignments.iter().enumerate() {
            let marker = if selected && j == 0 { "▸ " } else { "  " };
            let st = if selected {
                bold(GREEN)
            } else {
                Style::default().fg(GREEN)
            };
            lines.push(Line::from(vec![
                Span::styled(marker, Style::default().fg(TEAL)),
                Span::styled(a.describe(), st),
            ]));
        }
        for e in &sug.effects {
            lines.push(Line::styled(
                format!("      → {}", e.describe()),
                Style::default().fg(PINK),
            ));
        }
    }
    let width = lines
        .iter()
        .map(|l| u16_of(l.width()))
        .max()
        .unwrap_or(40)
        .max(56)
        + 4;
    // Like the facts it's about, anchor the popup left of center.
    let mut rect = popup(
        area,
        width.max(area.width * 3 / 5),
        u16_of(lines.len()).saturating_add(2),
    );
    rect.x = (area.x + area.width / 5).min(area.right().saturating_sub(rect.width));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(FG))
        .title(Span::styled(" suggest ", theme::fg()))
        .title_bottom(Span::styled(
            " ↑↓ choose   ⏎ apply   esc close ",
            theme::fg(),
        ));
    f.render_widget(Clear, rect);
    f.render_widget(Paragraph::new(lines).block(block), rect);
}

fn draw_help(f: &mut Frame<'_>, area: Rect) {
    let rows: &[(&str, &str)] = &[
        ("↑↓ / j k", "move between facts, or between policies"),
        ("← → / tab", "switch pane"),
        (
            "⏎",
            "edit the selected fact / suggest bindings for the selected policy",
        ),
        (
            "1",
            "type a value for the selected fact (tab cycles states while editing)",
        ),
        ("2", "mark it present with an unknown value (?)"),
        ("3", "mark it absent"),
        ("4", "mark it unknown"),
        ("s", "suggest values for the selected fact (SymCC + CVC5)"),
        ("u", "undo"),
        ("r / ctrl-r", "redo"),
        ("v", "cycle Residuals / Policies / Schema"),
        ("q", "quit"),
    ];
    let mut lines = vec![
        Line::styled(
            "◀ marks facts a policy still needs.  ◆ residual  ✓ satisfied  × not satisfied",
            muted(),
        ),
        Line::raw(""),
    ];
    for (k, d) in rows {
        lines.push(Line::from(vec![
            Span::styled(format!("{k:>10}  "), Style::default().fg(TEAL)),
            Span::styled(*d, theme::fg()),
        ]));
    }
    let rect = popup(area, 84, u16_of(lines.len()).saturating_add(2));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(FG))
        .title(Span::styled(" help ", theme::fg()))
        .title_bottom(Span::styled(" any key to close ", muted()));
    f.render_widget(Clear, rect);
    f.render_widget(Paragraph::new(lines).block(block), rect);
}

/// Saturating conversion for terminal coordinates.
fn u16_of(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}
