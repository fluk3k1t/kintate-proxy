use crate::policy::{Action, AccessSession, DomainTag, Policy, Rule, RuleData};
use crate::limit::{LimitManager, LimitRule};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs},
    Terminal,
};
use std::{error::Error, io, time::{Duration, Instant}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Rules,
    Logs,
    Tags,
    Limits,
}

impl Tab {
    fn all() -> Vec<Tab> {
        vec![Tab::Rules, Tab::Logs, Tab::Tags, Tab::Limits]
    }

    fn title(&self) -> &'static str {
        match self {
            Tab::Rules => " Rules (P) ",
            Tab::Logs => " Logs (L) ",
            Tab::Tags => " Tags (T) ",
            Tab::Limits => " Limits (U) ",
        }
    }
}

#[derive(PartialEq, Eq, Clone)]
enum InputMode {
    Viewing,
    AddingRule,
    EditingRule(i64),
    AddingTag,
    EditingTag(String),
    AddingLimit,
    EditingLimit(String),
}

pub struct App {
    policy: Policy,
    limit_manager: LimitManager,
    active_tab: Tab,
    input_mode: InputMode,
    should_quit: bool,

    rules: Vec<std::sync::Arc<Rule>>,
    logs: Vec<AccessSession>,
    tags: Vec<DomainTag>,
    limits: Vec<LimitRule>,

    // Selection states
    rule_state: TableState,
    log_state: TableState,
    tag_state: TableState,
    limit_state: TableState,

    // Form states
    form_fields: Vec<(String, String)>, // (Label, Value)
    form_focus: usize,

    last_update: Instant,
}

impl App {
    pub fn new(policy: Policy, limit_manager: LimitManager) -> Self {
        Self {
            policy,
            limit_manager,
            active_tab: Tab::Rules,
            input_mode: InputMode::Viewing,
            should_quit: false,
            rules: Vec::new(),
            logs: Vec::new(),
            tags: Vec::new(),
            limits: Vec::new(),
            rule_state: TableState::default().with_selected(Some(0)),
            log_state: TableState::default().with_selected(Some(0)),
            tag_state: TableState::default().with_selected(Some(0)),
            limit_state: TableState::default().with_selected(Some(0)),
            form_fields: Vec::new(),
            form_focus: 0,
            last_update: Instant::now(),
        }
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        self.refresh_data();

        let tick_rate = Duration::from_millis(250);
        let mut last_tick = Instant::now();

        loop {
            terminal.draw(|f| self.ui(f))?;

            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != event::KeyEventKind::Press {
                        continue;
                    }

                    match self.input_mode {
                        InputMode::Viewing => match key.code {
                            KeyCode::Char('q') => self.should_quit = true,
                            KeyCode::Char('p') => self.active_tab = Tab::Rules,
                            KeyCode::Char('l') => self.active_tab = Tab::Logs,
                            KeyCode::Char('t') => self.active_tab = Tab::Tags,
                            KeyCode::Char('u') => self.active_tab = Tab::Limits,
                            KeyCode::Tab => self.next_tab(),
                            KeyCode::Char('r') => self.refresh_data(),
                            KeyCode::Char('a') => self.init_add_mode(),
                            KeyCode::Char('e') => self.init_edit_mode(),
                            KeyCode::Char('d') => self.delete_selected()?,
                            KeyCode::Up => self.move_selection(-1),
                            KeyCode::Down => self.move_selection(1),
                            _ => {}
                        },
                        _ => match key.code {
                            KeyCode::Esc => self.input_mode = InputMode::Viewing,
                            KeyCode::Tab | KeyCode::Down => {
                                self.form_focus = (self.form_focus + 1) % self.form_fields.len();
                            }
                            KeyCode::Up => {
                                self.form_focus = if self.form_focus == 0 {
                                    self.form_fields.len() - 1
                                } else {
                                    self.form_focus - 1
                                };
                            }
                            KeyCode::Enter => {
                                if self.form_focus == self.form_fields.len() - 1 {
                                    self.submit_form()?;
                                } else {
                                    self.form_focus =
                                        (self.form_focus + 1) % (self.form_fields.len());
                                }
                            }
                            KeyCode::Char(c) => {
                                if self.form_focus < self.form_fields.len() - 1 {
                                    self.form_fields[self.form_focus].1.push(c);
                                }
                            }
                            KeyCode::Backspace => {
                                if self.form_focus < self.form_fields.len() - 1 {
                                    self.form_fields[self.form_focus].1.pop();
                                }
                            }
                            _ => {}
                        },
                    }
                }
            }

            if last_tick.elapsed() >= tick_rate {
                last_tick = Instant::now();
            }

            if self.should_quit {
                break;
            }

            if self.last_update.elapsed() > Duration::from_secs(5) {
                self.refresh_data();
            }
        }

        // restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        Ok(())
    }

    fn move_selection(&mut self, delta: i32) {
        let (state, len) = match self.active_tab {
            Tab::Rules => (&mut self.rule_state, self.rules.len()),
            Tab::Logs => (&mut self.log_state, self.logs.len()),
            Tab::Tags => (&mut self.tag_state, self.tags.len()),
            Tab::Limits => (&mut self.limit_state, self.limits.len()),
        };

        if len == 0 {
            return;
        }

        let i = match state.selected() {
            Some(i) => {
                let next = i as i32 + delta;
                if next < 0 {
                    0
                } else if next >= len as i32 {
                    len - 1
                } else {
                    next as usize
                }
            }
            None => 0,
        };
        state.select(Some(i));
    }

    fn init_add_mode(&mut self) {
        match self.active_tab {
            Tab::Rules => {
                self.input_mode = InputMode::AddingRule;
                self.form_fields = vec![
                    ("Priority".to_string(), "100".to_string()),
                    ("Action (Allow/Block)".to_string(), "Block".to_string()),
                    ("Domain".to_string(), "".to_string()),
                    ("Tag".to_string(), "".to_string()),
                    ("Name".to_string(), "".to_string()),
                    ("[Submit]".to_string(), "".to_string()),
                ];
            }
            Tab::Tags => {
                self.input_mode = InputMode::AddingTag;
                self.form_fields = vec![
                    ("SLD".to_string(), "".to_string()),
                    ("Tag Name".to_string(), "".to_string()),
                    ("[Submit]".to_string(), "".to_string()),
                ];
            }
            Tab::Limits => {
                self.input_mode = InputMode::AddingLimit;
                self.form_fields = vec![
                    ("Tag Name".to_string(), "".to_string()),
                    ("Max Minutes/Day".to_string(), "60".to_string()),
                    ("[Submit]".to_string(), "".to_string()),
                ];
            }
            _ => {}
        }
        self.form_focus = 0;
    }

    fn init_edit_mode(&mut self) {
        match self.active_tab {
            Tab::Rules => {
                if let Some(i) = self.rule_state.selected() {
                    if let Some(rule) = self.rules.get(i) {
                        self.input_mode = InputMode::EditingRule(rule.id);
                        self.form_fields = vec![
                            ("Priority".to_string(), rule.data.priority.to_string()),
                            ("Action".to_string(), rule.data.action.as_str().to_string()),
                            ("Domain".to_string(), rule.data.domain.as_deref().unwrap_or("").to_string()),
                            ("Tag".to_string(), rule.data.tag.as_deref().unwrap_or("").to_string()),
                            ("Name".to_string(), rule.data.name.as_deref().unwrap_or("").to_string()),
                            ("[Update]".to_string(), "".to_string()),
                        ];
                    }
                }
            }
            Tab::Tags => {
                if let Some(i) = self.tag_state.selected() {
                    if let Some(tag) = self.tags.get(i) {
                        self.input_mode = InputMode::EditingTag(tag.sld.clone());
                        self.form_fields = vec![
                            ("SLD (Read-only)".to_string(), tag.sld.clone()),
                            ("Tag Name".to_string(), tag.tag.clone()),
                            ("[Update]".to_string(), "".to_string()),
                        ];
                    }
                }
            }
            Tab::Limits => {
                if let Some(i) = self.limit_state.selected() {
                    if let Some(limit) = self.limits.get(i) {
                        self.input_mode = InputMode::EditingLimit(limit.tag.clone());
                        self.form_fields = vec![
                            ("Tag (Read-only)".to_string(), limit.tag.clone()),
                            ("Max Minutes/Day".to_string(), (limit.max_duration_secs / 60).to_string()),
                            ("[Update]".to_string(), "".to_string()),
                        ];
                    }
                }
            }
            _ => {}
        }
        self.form_focus = 0;
    }

    fn delete_selected(&mut self) -> Result<(), Box<dyn Error>> {
        match self.active_tab {
            Tab::Rules => {
                if let Some(i) = self.rule_state.selected() {
                    if let Some(r) = self.rules.get(i) {
                        self.policy.delete_rule(r.id)?;
                    }
                }
            }
            Tab::Tags => {
                if let Some(i) = self.tag_state.selected() {
                    if let Some(t) = self.tags.get(i) {
                        self.policy.delete_domain_tag(&t.sld)?;
                    }
                }
            }
            Tab::Limits => {
                if let Some(i) = self.limit_state.selected() {
                    if let Some(l) = self.limits.get(i) {
                        self.limit_manager.delete_limit(&l.tag)?;
                    }
                }
            }
            Tab::Logs => {
                self.policy.clear_access_logs()?;
            }
        }
        self.refresh_data();
        Ok(())
    }

    fn submit_form(&mut self) -> Result<(), Box<dyn Error>> {
        match self.input_mode.clone() {
            InputMode::AddingRule | InputMode::EditingRule(_) => {
                let priority: i32 = self.form_fields[0].1.parse().unwrap_or(100);
                let action = if self.form_fields[1].1.to_lowercase() == "allow" {
                    Action::Allow
                } else {
                    Action::Block
                };
                let domain = if self.form_fields[2].1.is_empty() { None } else { Some(self.form_fields[2].1.clone()) };
                let tag = if self.form_fields[3].1.is_empty() { None } else { Some(self.form_fields[3].1.clone()) };
                let name = if self.form_fields[4].1.is_empty() { None } else { Some(self.form_fields[4].1.clone()) };

                let data = RuleData {
                    priority,
                    action,
                    name,
                    domain,
                    tag,
                    path_pattern: None,
                    client_ip: None,
                };

                if let InputMode::EditingRule(id) = self.input_mode {
                    self.policy.update_rule(id, data)?;
                } else {
                    self.policy.insert_rule(data)?;
                }
            }
            InputMode::AddingTag | InputMode::EditingTag(_) => {
                let sld = self.form_fields[0].1.trim().to_lowercase();
                let tag = self.form_fields[1].1.trim().to_string();
                if !sld.is_empty() && !tag.is_empty() {
                    self.policy.add_domain_tag(&sld, &tag)?;
                }
            }
            InputMode::AddingLimit | InputMode::EditingLimit(_) => {
                let tag = self.form_fields[0].1.trim().to_string();
                let mins: i64 = self.form_fields[1].1.parse().unwrap_or(0);
                if !tag.is_empty() && mins > 0 {
                    self.limit_manager.add_limit(&tag, mins * 60)?;
                }
            }
            _ => {}
        }
        self.input_mode = InputMode::Viewing;
        self.refresh_data();
        Ok(())
    }

    fn next_tab(&mut self) {
        let tabs = Tab::all();
        let current_index = tabs.iter().position(|&t| t == self.active_tab).unwrap();
        self.active_tab = tabs[(current_index + 1) % tabs.len()];
    }

    fn refresh_data(&mut self) {
        self.rules = self.policy.get_all_rules();
        self.logs = self
            .policy
            .get_access_logs(50, None, None)
            .unwrap_or_default();
        self.tags = self.policy.get_all_domain_tags().unwrap_or_default();
        self.limits = self.limit_manager.get_all_limits().unwrap_or_default();
        self.last_update = Instant::now();
    }

    fn ui(&mut self, f: &mut ratatui::Frame) {
        let size = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Content
                Constraint::Length(1), // Footer
            ])
            .split(size);

        // Header / Tabs
        let titles: Vec<Line> = Tab::all()
            .into_iter()
            .map(|t| {
                let style = if t == self.active_tab {
                    Style::default()
                        .bg(Color::Blue)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                Line::from(vec![Span::styled(t.title(), style)])
            })
            .collect();

        let tabs = Tabs::new(titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Kintate Proxy Manager "),
            )
            .select(
                Tab::all()
                    .into_iter()
                    .position(|t| t == self.active_tab)
                    .unwrap(),
            );
        f.render_widget(tabs, chunks[0]);

        // Content
        match self.active_tab {
            Tab::Rules => self.render_rules(f, chunks[1]),
            Tab::Logs => self.render_logs(f, chunks[1]),
            Tab::Tags => self.render_tags(f, chunks[1]),
            Tab::Limits => self.render_limits(f, chunks[1]),
        }

        // Footer
        let help_text = if self.input_mode == InputMode::Viewing {
            " [↑/↓] Select  [A] Add  [E] Edit  [D] Delete  [R] Refresh  [Q] Quit ".to_string()
        } else {
            " [Esc] Cancel  [Tab] Next Field  [Enter] Submit ".to_string()
        };
        let help = Paragraph::new(help_text);
        f.render_widget(help, chunks[2]);

        // Popup for editing
        if self.input_mode != InputMode::Viewing {
            self.render_popup(f, size);
        }
    }

    fn render_rules(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let header_cells = ["ID", "Pri", "Action", "Domain", "Tag", "Name"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
        let header = Row::new(header_cells).height(1).bottom_margin(1);

        let rows = self.rules.iter().map(|r| {
            let action_style = match r.data.action {
                Action::Allow => Style::default().fg(Color::Green),
                Action::Block => Style::default().fg(Color::Red),
            };
            Row::new(vec![
                Cell::from(r.id.to_string()),
                Cell::from(r.data.priority.to_string()),
                Cell::from(r.data.action.as_str()).style(action_style),
                Cell::from(r.data.domain.as_deref().unwrap_or("*")),
                Cell::from(r.data.tag.as_deref().unwrap_or("*")),
                Cell::from(r.data.name.as_deref().unwrap_or("-")),
            ])
        });

        let t = Table::new(
            rows,
            [
                Constraint::Length(4),
                Constraint::Length(4),
                Constraint::Length(8),
                Constraint::Percentage(30),
                Constraint::Percentage(20),
                Constraint::Percentage(30),
            ],
        )
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Firewall Rules "))
        .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

        f.render_stateful_widget(t, area, &mut self.rule_state);
    }

    fn render_logs(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let header_cells = ["Time", "IP", "Target / Tag", "Action", "Reqs"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
        let header = Row::new(header_cells).height(1).bottom_margin(1);

        let rows = self.logs.iter().map(|log| {
            Row::new(vec![
                Cell::from(log.last_access.format("%H:%M:%S").to_string()),
                Cell::from(log.device_ip.clone()),
                Cell::from(log.target_domain.clone()),
                Cell::from(log.action.as_str()),
                Cell::from(log.request_count.to_string()),
            ])
        });

        let t = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Length(16),
                Constraint::Percentage(50),
                Constraint::Length(8),
                Constraint::Length(6),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Session Activity (Flushed) "),
        );
        f.render_stateful_widget(t, area, &mut self.log_state);
    }

    fn render_tags(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let rows = self.tags.iter().map(|t| {
            Row::new(vec![
                Cell::from(t.id.to_string()),
                Cell::from(t.sld.clone()),
                Cell::from(t.tag.clone()),
            ])
        });

        let t = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Percentage(45),
                Constraint::Percentage(45),
            ],
        )
        .header(Row::new(vec!["ID", "SLD", "Tag Name"]).style(Style::default().fg(Color::Yellow)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Domain -> Tag Mappings "),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

        f.render_stateful_widget(t, area, &mut self.tag_state);
    }

    fn render_limits(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let rows = self.limits.iter().map(|l| {
            Row::new(vec![
                Cell::from(l.id.to_string()),
                Cell::from(l.tag.clone()),
                Cell::from(format!("{} min", l.max_duration_secs / 60)),
            ])
        });

        let t = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Percentage(45),
                Constraint::Percentage(45),
            ],
        )
        .header(Row::new(vec!["ID", "Tag", "Daily Limit"]).style(Style::default().fg(Color::Yellow)))
        .block(Block::default().borders(Borders::ALL).title(" Usage Time Limits "))
        .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

        f.render_stateful_widget(t, area, &mut self.limit_state);
    }

    fn render_popup(&self, f: &mut ratatui::Frame, area: Rect) {
        let title = match self.input_mode {
            InputMode::AddingRule | InputMode::AddingTag | InputMode::AddingLimit => " Add New Item ",
            _ => " Edit Item ",
        };

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .bg(Color::Black);
        let popup_area = self.centered_rect(60, 80, area);
        f.render_widget(block, popup_area);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints(
                self.form_fields
                    .iter()
                    .map(|_| Constraint::Length(3))
                    .collect::<Vec<_>>(),
            )
            .split(popup_area);

        for (i, (label, value)) in self.form_fields.iter().enumerate() {
            let is_last = i == self.form_fields.len() - 1;
            let is_focused = i == self.form_focus;

            if is_last {
                let style = if is_focused {
                    Style::default()
                        .bg(Color::Green)
                        .fg(Color::Black)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Green).add_modifier(Modifier::DIM)
                };

                let button = Paragraph::new(format!("  {}  ", label))
                    .alignment(ratatui::layout::Alignment::Center)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_type(ratatui::widgets::BorderType::Rounded),
                    )
                    .style(style);
                f.render_widget(button, inner_chunks[i]);
            } else {
                let style = if is_focused {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                let input = Paragraph::new(value.as_str())
                    .block(Block::default().borders(Borders::ALL).title(label.as_str()))
                    .style(style);
                f.render_widget(input, inner_chunks[i]);
            }
        }
    }

    fn centered_rect(&self, percent_x: u16, percent_y: u16, r: Rect) -> Rect {
        let popup_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ])
            .split(r);

        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ])
            .split(popup_layout[1])[1]
    }
}
