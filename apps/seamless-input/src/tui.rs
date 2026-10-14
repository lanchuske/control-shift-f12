use ratatui::{
    Terminal,
    backend::TestBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use seamless_input_core::{Display, DisplayId, Edge, NodeId, Point, Topology};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Unpaired,
    Paired,
    Online,
    Offline,
    Incompatible,
}

impl PeerState {
    fn label(self) -> &'static str {
        match self {
            Self::Unpaired => "unpaired",
            Self::Paired => "paired",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Incompatible => "incompatible",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayTile {
    pub peer: String,
    pub display: u32,
    pub x: i32,
    pub y: i32,
    pub state: PeerState,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TuiModel {
    pub available: Vec<DisplayTile>,
    pub tiles: Vec<DisplayTile>,
    pub selected_available: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorKey {
    Left,
    Right,
    Up,
    Down,
    Enter,
    Delete,
    Save,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorAction {
    Changed,
    Save,
    Quit,
    Rejected,
}

impl TuiModel {
    pub fn with_available(name: &str, state: PeerState) -> Self {
        Self {
            available: vec![DisplayTile {
                peer: name.into(),
                display: 0,
                x: 0,
                y: 0,
                state,
            }],
            ..Self::default()
        }
    }

    pub fn with_tiles(tiles: Vec<DisplayTile>) -> Self {
        Self {
            tiles,
            ..Self::default()
        }
    }

    pub fn with_error(message: &str) -> Self {
        Self {
            error: Some(message.into()),
            ..Self::default()
        }
    }

    pub fn handle(&mut self, key: EditorKey) -> EditorAction {
        self.error = None;
        match key {
            EditorKey::Save => EditorAction::Save,
            EditorKey::Quit => EditorAction::Quit,
            EditorKey::Delete => {
                if self.tiles.len() > 1 {
                    self.tiles.pop();
                }
                EditorAction::Changed
            }
            EditorKey::Enter => self.commit_selected(),
            direction => {
                let Some(tile) = self.available.get_mut(self.selected_available) else {
                    return EditorAction::Rejected;
                };
                match direction {
                    EditorKey::Left => tile.x = tile.x.saturating_sub(1),
                    EditorKey::Right => tile.x = tile.x.saturating_add(1),
                    EditorKey::Up => tile.y = tile.y.saturating_sub(1),
                    EditorKey::Down => tile.y = tile.y.saturating_add(1),
                    _ => unreachable!(),
                }
                EditorAction::Changed
            }
        }
    }

    fn commit_selected(&mut self) -> EditorAction {
        let Some(candidate) = self.available.get(self.selected_available).cloned() else {
            return EditorAction::Rejected;
        };
        let mut proposed = self.tiles.clone();
        proposed.push(candidate.clone());
        if let Err(message) = validate_with_core(&proposed) {
            self.error = Some(message.into());
            return EditorAction::Rejected;
        }
        self.tiles.push(candidate);
        self.available.remove(self.selected_available);
        self.selected_available = self
            .selected_available
            .min(self.available.len().saturating_sub(1));
        EditorAction::Changed
    }
}

fn validate_with_core(tiles: &[DisplayTile]) -> Result<(), &'static str> {
    let Some(root) = tiles.first() else {
        return Ok(());
    };
    let mut topology = Topology::new(core_display(root)).map_err(|_| "Invalid display")?;
    let mut placed = vec![root.clone()];
    let mut pending = tiles[1..].to_vec();
    while !pending.is_empty() {
        let Some((pending_index, anchor, edge)) =
            pending.iter().enumerate().find_map(|(index, tile)| {
                placed.iter().find_map(|anchor| {
                    edge_between((anchor.x, anchor.y), (tile.x, tile.y))
                        .map(|edge| (index, anchor.clone(), edge))
                })
            })
        else {
            return Err("Displays must touch on a cardinal edge");
        };
        let tile = pending.remove(pending_index);
        topology
            .place(core_id(&anchor), edge, core_display(&tile))
            .map_err(|error| match error {
                seamless_input_core::TopologyError::Collision => {
                    "That position is already occupied"
                }
                _ => "Invalid cardinal topology",
            })?;
        placed.push(tile);
    }
    Ok(())
}

fn edge_between(anchor: (i32, i32), candidate: (i32, i32)) -> Option<Edge> {
    match (candidate.0 - anchor.0, candidate.1 - anchor.1) {
        (-1, 0) => Some(Edge::Left),
        (1, 0) => Some(Edge::Right),
        (0, -1) => Some(Edge::Top),
        (0, 1) => Some(Edge::Bottom),
        _ => None,
    }
}

fn core_display(tile: &DisplayTile) -> Display {
    Display {
        id: core_id(tile),
        origin: Point { x: 0.0, y: 0.0 },
        width: 1.0,
        height: 1.0,
        scale: 1.0,
    }
}

fn core_id(tile: &DisplayTile) -> DisplayId {
    let mut bytes = [0_u8; 16];
    for (index, byte) in tile.peer.bytes().enumerate() {
        let slot = index % bytes.len();
        bytes[slot] = bytes[slot].wrapping_mul(31).wrapping_add(byte);
    }
    DisplayId {
        node: NodeId(bytes),
        index: tile.display,
    }
}

pub fn render_to_string(model: &TuiModel, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend construction cannot fail");
    terminal
        .draw(|frame| render(frame, model))
        .expect("test rendering cannot fail");
    let buffer = terminal.backend().buffer();
    let mut output = String::new();
    for y in 0..height {
        let mut line = String::new();
        for x in 0..width {
            line.push_str(buffer[(x, y)].symbol());
        }
        output.push_str(line.trim_end());
        output.push('\n');
    }
    output
}

pub fn render(frame: &mut ratatui::Frame<'_>, model: &TuiModel) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(48),
            Constraint::Percentage(24),
        ])
        .split(frame.area());
    render_available(frame, columns[0], model);
    render_canvas(frame, columns[1], model);
    render_help(frame, columns[2], model);
}

fn render_available(frame: &mut ratatui::Frame<'_>, area: Rect, model: &TuiModel) {
    let lines = if model.available.is_empty() {
        vec![Line::from("No discovered peers")]
    } else {
        model
            .available
            .iter()
            .enumerate()
            .map(|(index, peer)| {
                let marker = if index == model.selected_available {
                    ">"
                } else {
                    " "
                };
                Line::from(format!("{marker} {} · {}", peer.peer, peer.state.label()))
            })
            .collect()
    };
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Available peers "),
        ),
        area,
    );
}

fn render_canvas(frame: &mut ratatui::Frame<'_>, area: Rect, model: &TuiModel) {
    let mut lines = vec![Line::from(Span::styled(
        "Topology",
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    if model.tiles.is_empty() {
        lines.push(Line::from("No displays placed"));
        lines.push(Line::from("Select a paired peer and press Enter"));
    } else {
        let min_x = model.tiles.iter().map(|tile| tile.x).min().unwrap_or(0);
        let max_x = model.tiles.iter().map(|tile| tile.x).max().unwrap_or(0);
        let min_y = model.tiles.iter().map(|tile| tile.y).min().unwrap_or(0);
        let max_y = model.tiles.iter().map(|tile| tile.y).max().unwrap_or(0);
        for y in min_y..=max_y {
            let mut row = String::new();
            for x in min_x..=max_x {
                if let Some(tile) = model.tiles.iter().find(|tile| tile.x == x && tile.y == y) {
                    let name: String = tile.peer.chars().take(8).collect();
                    row.push_str(&format!("[{name}:{} {}]", tile.display, tile.state.label()));
                } else {
                    row.push_str("       ·       ");
                }
                row.push(' ');
            }
            lines.push(Line::from(row));
        }
    }
    if let Some(error) = &model.error {
        lines.push(Line::from(Span::styled(
            format!("Error: {error}"),
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Topology canvas "),
        ),
        area,
    );
}

fn render_help(frame: &mut ratatui::Frame<'_>, area: Rect, _model: &TuiModel) {
    let lines = vec![
        Line::from("Arrows  position"),
        Line::from("Enter   place"),
        Line::from("Delete  remove"),
        Line::from("S       save"),
        Line::from("Q       quit"),
        Line::from(""),
        Line::from("No administrator"),
        Line::from("permissions needed."),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Help ")),
        area,
    );
}
