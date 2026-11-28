mod pages;
mod widgets;

use crate::app::{App, Message, Page};
use crate::theme;
use crate::ui::widgets::{btn_tiny, short_cwd};
use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::Length::Fill;
use iced::{Element, Length};

impl App {
    pub(crate) fn view(&self) -> Element<'_, Message> {
        // Every text size goes through `theme::sz`, so setting the global
        // scale here is enough to resize the whole interface.
        theme::set_zoom(self.zoom);

        let content = match self.page {
            Page::Vaults => self.page_vaults(),
            Page::Files => self.page_files(),
            Page::Passwords => self.page_passwords(),
            Page::Security => self.page_security(),
        };

        column![
            self.navbar(),
            container(self.status_area(content))
                .width(Fill)
                .height(Fill)
                .padding([14, 16]),
        ]
        .into()
    }

    fn navbar(&self) -> Element<'_, Message> {
        let status = match self.notice.last() {
            Some((true, msg)) => text(format!("» {msg}"))
                .size(theme::sz(10.0))
                .color(theme::GREEN),
            Some((false, msg)) => text(format!("» {msg}"))
                .size(theme::sz(10.0))
                .color(theme::RED),
            None if crate::util::using_legacy_dir() => text("» legacy ~/.krypton data dir")
                .size(theme::sz(10.0))
                .color(theme::ACCENT),
            None => text(short_cwd()).size(theme::sz(10.0)).color(theme::ACCENT),
        };
        let zoom = row![
            btn_tiny("−", Message::ZoomOut),
            text(format!("{}%", self.zoom))
                .size(theme::sz(11.0))
                .color(theme::DIM),
            btn_tiny("+", Message::ZoomIn),
            btn_tiny("reset", Message::ZoomReset),
        ]
        .spacing(4)
        .align_y(iced::Alignment::Center);

        container(
            container(
                row![
                    text("KERES")
                        .size(theme::sz(14.0))
                        .color(theme::ACCENT)
                        .font(iced::Font {
                            weight: iced::font::Weight::Bold,
                            ..theme::MONO
                        }),
                    Space::new().width(Length::Fixed(14.0)),
                    self.nav_tab(Page::Vaults, "vault"),
                    self.nav_tab(Page::Passwords, "passwords"),
                    self.nav_tab(Page::Files, "containers"),
                    self.nav_tab(Page::Security, "security"),
                    Space::new().width(Fill),
                    zoom,
                    Space::new().width(Length::Fixed(12.0)),
                    status,
                ]
                .align_y(iced::Alignment::Center)
                .spacing(6),
            )
            .width(Fill)
            .padding([8, 12])
            .style(theme::panel),
        )
        .width(Fill)
        .padding([12, 16])
        .into()
    }

    fn nav_tab(&self, page: Page, label: &'static str) -> Element<'_, Message> {
        let active = self.page == page;
        let color = if active { theme::ACCENT } else { theme::DIM };
        button(text(label).size(theme::sz(13.0)).color(color))
            .padding([7, 14])
            .style(move |theme, status| theme::nav(active)(theme, status))
            .on_press(Message::Nav(page))
            .into()
    }

    fn status_area<'a>(&'a self, content: Element<'a, Message>) -> Element<'a, Message> {
        container(
            scrollable(content)
                .id(self.scroll_id.clone())
                .style(theme::scrollable_style)
                .width(Fill)
                .height(Fill),
        )
        .width(Fill)
        .height(Fill)
        .into()
    }

    // ---------------------------------------------------------------- pages
}
