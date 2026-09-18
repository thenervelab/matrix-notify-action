// Copyright 2026 The Nerve Lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Message construction: plain text, Markdown, and the compact GitHub run
//! card. Everything here is pure and covered by golden tests.

use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
use pulldown_cmark::{html, Options, Parser};

/// A message ready to be turned into an `m.room.message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Plain-text `body`, always present (fallback for clients without HTML).
    pub body: String,
    /// Optional `formatted_body` (format `org.matrix.custom.html`).
    pub html: Option<String>,
    /// `m.notice` (bot output, not highlighted) rather than `m.text`.
    pub notice: bool,
}

impl Message {
    pub fn plain(body: impl Into<String>, notice: bool) -> Self {
        Self { body: body.into(), html: None, notice }
    }

    /// Body is Markdown; render it to a `formatted_body`. If the Markdown is
    /// just a paragraph of text, no HTML is attached (nothing to gain).
    pub fn markdown(md: &str, notice: bool) -> Self {
        let html = markdown_to_html(md);
        let trivial = html == format!("<p>{}</p>", escape_html(md.trim()));
        Self { body: md.to_owned(), html: if trivial { None } else { Some(html) }, notice }
    }

    pub fn into_content(self) -> RoomMessageEventContent {
        match (self.notice, self.html) {
            (true, Some(h)) => RoomMessageEventContent::notice_html(self.body, h),
            (true, None) => RoomMessageEventContent::notice_plain(self.body),
            (false, Some(h)) => RoomMessageEventContent::text_html(self.body, h),
            (false, None) => RoomMessageEventContent::text_plain(self.body),
        }
    }
}

/// CommonMark + tables/strikethrough/task lists (what people paste from
/// GitHub). Raw HTML is passed through: Matrix clients sanitise on display,
/// and the sender is a trusted bot.
pub fn markdown_to_html(md: &str) -> String {
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    let parser = Parser::new_ext(md, opts);
    let mut out = String::with_capacity(md.len() * 3 / 2);
    html::push_html(&mut out, parser);
    out.trim_end().to_owned()
}

pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Job status, as `${{ job.status }}` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum Status {
    Success,
    Failure,
    Cancelled,
}

impl Status {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "success" | "succeeded" | "ok" | "passed" => Some(Self::Success),
            "failure" | "failed" | "error" => Some(Self::Failure),
            "cancelled" | "canceled" | "skipped" => Some(Self::Cancelled),
            _ => None,
        }
    }

    fn glyph(self) -> &'static str {
        match self {
            Self::Success => "✅",
            Self::Failure => "❌",
            Self::Cancelled => "⚠️",
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Self::Success => "succeeded",
            Self::Failure => "failed",
            Self::Cancelled => "was cancelled",
        }
    }
}

/// The GitHub Actions environment we render. Built from `GITHUB_*` variables
/// via [`RunInfo::from_env`], or directly in tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunInfo {
    pub server_url: String,
    pub repository: String,
    pub workflow: String,
    pub run_id: String,
    pub run_attempt: Option<String>,
    pub ref_name: String,
    pub sha: String,
    pub actor: String,
    pub job: Option<String>,
    pub event_name: Option<String>,
}

impl RunInfo {
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            server_url: get("GITHUB_SERVER_URL").unwrap_or_else(|| "https://github.com".into()),
            repository: get("GITHUB_REPOSITORY").unwrap_or_default(),
            workflow: get("GITHUB_WORKFLOW").unwrap_or_default(),
            run_id: get("GITHUB_RUN_ID").unwrap_or_default(),
            run_attempt: get("GITHUB_RUN_ATTEMPT").filter(|a| a != "1"),
            ref_name: get("GITHUB_REF_NAME").unwrap_or_default(),
            sha: get("GITHUB_SHA").unwrap_or_default(),
            actor: get("GITHUB_ACTOR").unwrap_or_default(),
            job: get("GITHUB_JOB"),
            event_name: get("GITHUB_EVENT_NAME"),
        }
    }

    pub fn run_url(&self) -> String {
        let mut u = format!("{}/{}/actions/runs/{}", self.server_url, self.repository, self.run_id);
        if let Some(a) = &self.run_attempt {
            u.push_str("/attempts/");
            u.push_str(a);
        }
        u
    }

    pub fn commit_url(&self) -> String {
        format!("{}/{}/commit/{}", self.server_url, self.repository, self.sha)
    }

    fn short_sha(&self) -> &str {
        let n = self.sha.len().min(7);
        &self.sha[..n]
    }

    /// Two lines of plain text plus an HTML card. `extra` is appended as a
    /// trailing paragraph (Markdown-rendered when `markdown` is set).
    pub fn render(&self, status: Status, extra: Option<&str>, markdown: bool) -> Message {
        let glyph = status.glyph();
        let verb = status.verb();
        let run_url = self.run_url();
        let where_ = match &self.job {
            Some(job) if job != &self.workflow => format!("{} / {}", self.workflow, job),
            _ => self.workflow.clone(),
        };

        let mut body = format!(
            "{glyph} {repo}: {where_} {verb} on {branch} ({sha}) by {actor}\n{run_url}",
            repo = self.repository,
            branch = self.ref_name,
            sha = self.short_sha(),
            actor = self.actor,
        );
        let mut html = format!(
            "{glyph} <b>{repo}</b>: <a href=\"{run_url}\">{where_}</a> {verb} on <code>{branch}</code> \
             (<a href=\"{commit}\">{sha}</a>) by {actor}",
            repo = escape_html(&self.repository),
            where_ = escape_html(&where_),
            branch = escape_html(&self.ref_name),
            commit = escape_html(&self.commit_url()),
            sha = escape_html(self.short_sha()),
            actor = escape_html(&self.actor),
            run_url = escape_html(&run_url),
        );

        if let Some(extra) = extra.map(str::trim).filter(|s| !s.is_empty()) {
            body.push('\n');
            body.push_str(extra);
            html.push_str("<br>");
            if markdown {
                html.push_str(&markdown_to_html(extra));
            } else {
                html.push_str(&escape_html(extra).replace('\n', "<br>"));
            }
        }

        Message { body, html: Some(html), notice: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> RunInfo {
        RunInfo {
            server_url: "https://github.com".into(),
            repository: "acme/widgets".into(),
            workflow: "CI".into(),
            run_id: "1234567890".into(),
            run_attempt: None,
            ref_name: "main".into(),
            sha: "0123456789abcdef0123456789abcdef01234567".into(),
            actor: "octocat".into(),
            job: Some("build".into()),
            event_name: Some("push".into()),
        }
    }

    #[test]
    fn github_run_golden_success() {
        let m = info().render(Status::Success, None, false);
        assert!(m.notice);
        assert_eq!(
            m.body,
            "✅ acme/widgets: CI / build succeeded on main (0123456) by octocat\n\
             https://github.com/acme/widgets/actions/runs/1234567890"
        );
        assert_eq!(
            m.html.as_deref().unwrap(),
            "✅ <b>acme/widgets</b>: <a href=\"https://github.com/acme/widgets/actions/runs/1234567890\">CI / build</a> \
             succeeded on <code>main</code> \
             (<a href=\"https://github.com/acme/widgets/commit/0123456789abcdef0123456789abcdef01234567\">0123456</a>) by octocat"
        );
    }

    #[test]
    fn github_run_golden_failure_with_extra_and_attempt() {
        let mut i = info();
        i.run_attempt = Some("2".into());
        i.job = None;
        let m = i.render(Status::Failure, Some("  see *logs* & retry\n"), true);
        assert_eq!(
            m.body,
            "❌ acme/widgets: CI failed on main (0123456) by octocat\n\
             https://github.com/acme/widgets/actions/runs/1234567890/attempts/2\n\
             see *logs* & retry"
        );
        assert_eq!(
            m.html.as_deref().unwrap(),
            "❌ <b>acme/widgets</b>: <a href=\"https://github.com/acme/widgets/actions/runs/1234567890/attempts/2\">CI</a> \
             failed on <code>main</code> \
             (<a href=\"https://github.com/acme/widgets/commit/0123456789abcdef0123456789abcdef01234567\">0123456</a>) by octocat\
             <br><p>see <em>logs</em> &amp; retry</p>"
        );
    }

    #[test]
    fn github_run_cancelled_escapes_html_in_fields() {
        let mut i = info();
        i.ref_name = "feat/<b>x</b>".into();
        i.job = Some("CI".into()); // same as workflow: not repeated
        let m = i.render(Status::Cancelled, Some("a<b"), false);
        assert!(m.body.starts_with("⚠️ acme/widgets: CI was cancelled on feat/<b>x</b>"));
        let h = m.html.unwrap();
        assert!(h.contains("<code>feat/&lt;b&gt;x&lt;/b&gt;</code>"), "{h}");
        assert!(h.ends_with("<br>a&lt;b"), "{h}");
        assert!(!h.contains("CI / CI"));
    }

    #[test]
    fn from_lookup_defaults() {
        let i = RunInfo::from_lookup(|k| match k {
            "GITHUB_REPOSITORY" => Some("a/b".into()),
            "GITHUB_RUN_ATTEMPT" => Some("1".into()),
            _ => None,
        });
        assert_eq!(i.server_url, "https://github.com");
        assert_eq!(i.run_attempt, None, "attempt 1 is the default and not shown");
        assert_eq!(i.run_url(), "https://github.com/a/b/actions/runs/");
        assert_eq!(i.short_sha(), "");
    }

    #[test]
    fn status_parsing() {
        assert_eq!(Status::parse("Success"), Some(Status::Success));
        assert_eq!(Status::parse("failure"), Some(Status::Failure));
        assert_eq!(Status::parse("cancelled"), Some(Status::Cancelled));
        assert_eq!(Status::parse("canceled"), Some(Status::Cancelled));
        assert_eq!(Status::parse("weird"), None);
    }

    #[test]
    fn markdown_rendering() {
        assert_eq!(
            markdown_to_html("**bold** and `code`"),
            "<p><strong>bold</strong> and <code>code</code></p>"
        );
        assert_eq!(
            markdown_to_html("- [x] done\n- [ ] todo"),
            "<ul>\n<li><input disabled=\"\" type=\"checkbox\" checked=\"\"/>\ndone</li>\n<li><input disabled=\"\" type=\"checkbox\"/>\ntodo</li>\n</ul>"
        );
        assert_eq!(markdown_to_html("~~gone~~"), "<p><del>gone</del></p>");
        assert_eq!(
            markdown_to_html("| a | b |\n|---|---|\n| 1 | 2 |"),
            "<table><thead><tr><th>a</th><th>b</th></tr></thead><tbody>\n<tr><td>1</td><td>2</td></tr>\n</tbody></table>"
        );
        assert_eq!(
            markdown_to_html("[run](https://example.org/x)"),
            "<p><a href=\"https://example.org/x\">run</a></p>"
        );
    }

    #[test]
    fn markdown_message_skips_html_when_trivial() {
        let m = Message::markdown("just text", true);
        assert_eq!(m.html, None);
        let m = Message::markdown("with *emphasis*", false);
        assert_eq!(m.html.as_deref(), Some("<p>with <em>emphasis</em></p>"));
        assert!(!m.notice);
        // Text that only needs escaping is still trivial.
        let m = Message::markdown("a < b & c", true);
        assert_eq!(m.html, None);
    }

    #[test]
    fn into_content_msgtype() {
        use matrix_sdk::ruma::events::room::message::MessageType;
        let c = Message::plain("hi", true).into_content();
        assert!(matches!(c.msgtype, MessageType::Notice(_)));
        let c = Message::markdown("**hi**", false).into_content();
        match c.msgtype {
            MessageType::Text(t) => assert!(t.formatted.is_some()),
            _ => panic!("expected m.text"),
        }
    }
}
