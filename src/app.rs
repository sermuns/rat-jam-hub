use ratatui::prelude::*;
use ratatui::widgets::{Block, Clear, Paragraph, Widget};

pub struct App {
    pub counter: usize,
}

impl App {
    pub fn new() -> App {
        Self { counter: 0 }
    }
}

impl Widget for &App {
    fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer) {
        let style = match self.counter % 3 {
            0 => Style::default().red(),
            1 => Style::default().blue(),
            _ => Style::default(),
        };

        Clear.render(area, buf);

        Paragraph::new(format!("Counter: {}", self.counter))
            .centered()
            .block(Block::bordered().title("Press 'c' to reset the counter!"))
            .style(style)
            .render(area, buf);
    }
}
