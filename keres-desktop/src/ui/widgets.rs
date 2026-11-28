use crate::app::{Message, PageStatus};
use crate::theme;
use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::Length::Fill;
use iced::{Element, Length};
pub(crate) fn panel<'a>(
    title: &'a str,
    content: impl Into<Element<'a, Message>>,
) -> iced::widget::container::Container<'a, Message> {
    let mut children: Vec<Element<'a, Message>> = Vec::new();
    if !title.is_empty() {
        children.push(panel_head(title));
        children.push(Space::new().height(Length::Fixed(10.0)).into());
    }
    children.push(content.into());
    container(column(children))
        .style(theme::panel)
        .padding(20)
        .width(Fill)
}

pub(crate) fn panel_head<'a>(s: &'a str) -> Element<'a, Message> {
    text(s).size(theme::sz(11.0)).color(theme::FAINT).into()
}

pub(crate) fn field_label<'a>(s: &'a str) -> Element<'a, Message> {
    text(s).size(theme::sz(11.0)).color(theme::DIM).into()
}

pub(crate) fn short_cwd() -> String {
    let cwd = std::env::current_dir().ok();
    let home = std::env::var("HOME").ok();
    match (cwd, home) {
        (Some(cwd), Some(home)) => {
            let cwd = cwd.display().to_string();
            if cwd == home {
                "~".to_string()
            } else if let Some(rest) = cwd.strip_prefix(&home) {
                format!("~{rest}")
            } else {
                cwd
            }
        }
        (Some(cwd), None) => cwd.display().to_string(),
        _ => ".".to_string(),
    }
}

pub(crate) fn card<'a>(
    content: impl Into<Element<'a, Message>>,
) -> iced::widget::container::Container<'a, Message> {
    container(content)
        .style(theme::card)
        .padding(12)
        .width(Fill)
}

pub(crate) fn field<'a>(
    label: &'a str,
    control: impl Into<Element<'a, Message>>,
) -> iced::widget::container::Container<'a, Message> {
    container(column![
        field_label(label),
        Space::new().height(Length::Fixed(6.0)),
        control.into(),
    ])
    .style(theme::card)
    .padding(12)
    .width(Fill)
}

pub(crate) fn hline<'a>() -> Element<'a, Message> {
    container(Space::new().width(Fill).height(Length::Fixed(1.0)))
        .style(theme::divider_faint)
        .into()
}

pub(crate) fn status_line<'a>(st: &'a PageStatus) -> Element<'a, Message> {
    if st.is_empty() {
        return Space::new().height(Length::Fixed(20.0)).into();
    }
    let color = theme::status_color(st.kind);
    row![
        text("● ").size(theme::sz(11.0)).color(color),
        text(&st.text).size(theme::sz(12.0)).color(color),
    ]
    .align_y(iced::Alignment::Center)
    .into()
}

pub(crate) fn input<'a>(
    placeholder: &'a str,
    value: &'a str,
    on_input: fn(String) -> Message,
    secure: bool,
) -> iced::widget::text_input::TextInput<'a, Message> {
    text_input(placeholder, value)
        .on_input(on_input)
        .secure(secure)
        .padding([9, 12])
        .size(theme::sz(13.0))
        .style(theme::input_style)
}

pub(crate) fn btn_p<'a>(label: &'a str, msg: Message) -> Element<'a, Message> {
    button(text(label).size(theme::sz(13.0)).color(theme::ACCENT_DARK))
        .on_press(msg)
        .padding([9, 16])
        .style(theme::primary)
        .into()
}

pub(crate) fn btn_g<'a>(label: &'a str, msg: Message) -> Element<'a, Message> {
    button(text(label).size(theme::sz(13.0)).color(theme::DIM))
        .on_press(msg)
        .padding([9, 16])
        .style(theme::ghost)
        .into()
}

pub(crate) fn btn_tiny<'a>(label: &'a str, msg: Message) -> Element<'a, Message> {
    button(text(label).size(theme::sz(11.0)).color(theme::DIM))
        .on_press(msg)
        .padding([5, 10])
        .style(theme::ghost)
        .into()
}

pub(crate) fn btn_red<'a>(label: &'a str, msg: Message) -> Element<'a, Message> {
    button(text(label).size(theme::sz(11.0)).color(theme::RED))
        .on_press(msg)
        .padding([5, 10])
        .style(theme::danger)
        .into()
}
