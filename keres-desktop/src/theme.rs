use std::sync::atomic::{AtomicU16, Ordering};

use iced::theme::Palette;
use iced::widget::{button, checkbox, container, pick_list, scrollable, slider, text_input};
use iced::{Background, Border, Color, Font, Shadow, Theme};

// Gruvbox material palette, because i like it:
// pub const BG: Color = Color::from_rgb8(0x1D, 0x20, 0x21);
// pub const BG_SUNK: Color = Color::from_rgb8(0x14, 0x16, 0x17);
// pub const BG_PANEL: Color = Color::from_rgb8(0x28, 0x28, 0x28);
// pub const BG_RAISED: Color = Color::from_rgb8(0x32, 0x30, 0x2F);
// pub const BORDER: Color = Color::from_rgb8(0x3C, 0x38, 0x36);
// pub const BORDER_HI: Color = Color::from_rgb8(0x3C, 0x38, 0x36);
// pub const TEXT: Color = Color::from_rgb8(0xD4, 0xBE, 0x98);
// pub const DIM: Color = Color::from_rgb8(0xDD, 0xC7, 0xA1);
// pub const FAINT: Color = Color::from_rgb8(0xA8, 0x99, 0x84);
// pub const ACCENT: Color = Color::from_rgb8(0xE7, 0x8A, 0x4E);
// pub const ACCENT_HI: Color = Color::from_rgb8(0xEA, 0x69, 0x62);
// pub const ACCENT_DARK: Color = Color::from_rgb8(0x14, 0x16, 0x17);
// pub const GREEN: Color = Color::from_rgb8(0xA9, 0xB6, 0x65);
// pub const AMBER: Color = Color::from_rgb8(0xE7, 0x8A, 0x4E);
// pub const RED: Color = Color::from_rgb8(0xEA, 0x69, 0x62);

pub const BG: Color = Color::from_rgb8(0x1D, 0x20, 0x21); // bg0
pub const BG_SUNK: Color = Color::from_rgb8(0x1D, 0x20, 0x21); // deepest surface
pub const BG_PANEL: Color = Color::from_rgb8(0x28, 0x28, 0x28); // bg1
pub const BG_RAISED: Color = Color::from_rgb8(0x32, 0x30, 0x2F); // bg2

pub const BORDER: Color = Color::from_rgb8(0x3C, 0x38, 0x36); // bg3
pub const BORDER_HI: Color = Color::from_rgb8(0x50, 0x49, 0x45); // bg4

pub const TEXT: Color = Color::from_rgb8(0xD4, 0xBE, 0x98); // fg
pub const DIM: Color = Color::from_rgb8(0xA8, 0x99, 0x84); // gray
                                                           //pub const FAINT: Color = Color::from_rgb8(0x66, 0x5C, 0x54);     // muted gray
pub const FAINT: Color = Color::from_rgb8(0xA8, 0x99, 0x84);

pub const ACCENT: Color = Color::from_rgb8(0xE7, 0x8A, 0x4E); // orange
pub const ACCENT_HI: Color = Color::from_rgb8(0xEA, 0x69, 0x62); // red
pub const ACCENT_DARK: Color = Color::from_rgb8(0x50, 0x49, 0x45); // darker neutral

pub const GREEN: Color = Color::from_rgb8(0xA9, 0xB6, 0x65);
pub const AMBER: Color = Color::from_rgb8(0xD8, 0xA6, 0x57); // yellow
pub const RED: Color = Color::from_rgb8(0xEA, 0x69, 0x62);

pub const MONO: Font = Font::MONOSPACE;

// ----------------------------------------------------------------------------
// Zoom
// ----------------------------------------------------------------------------

/// Global text scale in percent. The view sets this from `App::zoom` before it
/// builds widgets, and every text size goes through [`sz`].
static ZOOM_PERCENT: AtomicU16 = AtomicU16::new(115);

pub fn set_zoom(percent: u16) {
    ZOOM_PERCENT.store(percent.clamp(80, 300), Ordering::Relaxed);
}

#[must_use]
pub fn zoom_percent() -> u16 {
    ZOOM_PERCENT.load(Ordering::Relaxed)
}

/// Scales a design-time text size by the current zoom level.
#[must_use]
pub fn sz(base: f32) -> f32 {
    base * zoom_percent() as f32 / 100.0
}

pub fn app_theme() -> Theme {
    Theme::custom(
        "keres ink",
        Palette {
            background: BG,
            text: TEXT,
            primary: ACCENT,
            success: GREEN,
            warning: AMBER,
            danger: RED,
        },
    )
}

// ----------------------------------------------------------------------------
// Containers
// ----------------------------------------------------------------------------

pub fn panel(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_PANEL)),
        border: Border::default().color(BORDER).width(1.0).rounded(0),
        ..Default::default()
    }
}

pub fn card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_RAISED)),
        border: Border::default().color(BORDER).width(1.0).rounded(0),
        ..Default::default()
    }
}

pub fn divider_faint(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BORDER_HI)),
        ..Default::default()
    }
}

// ----------------------------------------------------------------------------
// Buttons
// ----------------------------------------------------------------------------

pub fn primary(_theme: &Theme, status: button::Status) -> button::Style {
    let base = || button::Style {
        text_color: ACCENT_DARK,
        background: Some(Background::Color(ACCENT)),
        border: Border::default().color(ACCENT).width(1.0).rounded(0),
        shadow: Shadow::default(),
        snap: false,
    };
    match status {
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(ACCENT_HI)),
            ..base()
        },
        button::Status::Pressed => button::Style {
            background: Some(Background::Color(ACCENT)),
            text_color: ACCENT_DARK,
            ..base()
        },
        button::Status::Disabled => button::Style {
            text_color: FAINT,
            background: Some(Background::Color(BG_RAISED)),
            border: Border::default().color(BORDER).width(1.0).rounded(0),
            shadow: Shadow::default(),
            snap: false,
        },
        _ => base(),
    }
}

pub fn ghost(_theme: &Theme, status: button::Status) -> button::Style {
    let base = || button::Style {
        text_color: DIM,
        background: None,
        border: Border::default().color(BORDER).width(1.0).rounded(0),
        shadow: Shadow::default(),
        snap: false,
    };
    match status {
        button::Status::Hovered => button::Style {
            text_color: TEXT,
            background: Some(Background::Color(BG_RAISED)),
            border: Border::default().color(BORDER).width(1.0).rounded(0),
            ..base()
        },
        button::Status::Pressed => button::Style {
            text_color: ACCENT,
            background: Some(Background::Color(BG_SUNK)),
            ..base()
        },
        button::Status::Disabled => button::Style {
            text_color: FAINT,
            background: None,
            border: Border::default().color(BORDER).width(1.0).rounded(0),
            shadow: Shadow::default(),
            snap: false,
        },
        _ => base(),
    }
}

pub fn danger(_theme: &Theme, status: button::Status) -> button::Style {
    let base = || button::Style {
        text_color: RED,
        background: Some(Background::Color(BG_SUNK)),
        border: Border::default().color(RED).width(1.0).rounded(0),
        shadow: Shadow::default(),
        snap: false,
    };
    match status {
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(RED)),
            text_color: ACCENT_DARK,
            ..base()
        },
        button::Status::Pressed => button::Style {
            background: Some(Background::Color(BG_RAISED)),
            ..base()
        },
        button::Status::Disabled => button::Style {
            text_color: FAINT,
            background: None,
            border: Border::default().color(BORDER).width(1.0).rounded(0),
            shadow: Shadow::default(),
            snap: false,
        },
        _ => base(),
    }
}

pub fn nav(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        if active {
            button::Style {
                text_color: ACCENT,
                background: Some(Background::Color(BG_RAISED)),
                border: Border::default().color(ACCENT).width(1.0).rounded(0),
                shadow: Shadow::default(),
                snap: false,
            }
        } else {
            ghost(theme, status)
        }
    }
}

// ----------------------------------------------------------------------------
// Inputs
// ----------------------------------------------------------------------------

pub fn input_style(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    let focused = matches!(status, text_input::Status::Focused { .. });
    let (border_color, width) = if focused {
        (ACCENT, 1.0)
    } else {
        (BORDER_HI, 0.0)
    };
    text_input::Style {
        background: Background::Color(BG_SUNK),
        border: Border::default()
            .color(border_color)
            .width(width)
            .rounded(0),
        icon: DIM,
        placeholder: FAINT,
        value: TEXT,
        selection: Color::from_rgba8(0xFF, 0x6B, 0x3D, 0.35),
    }
}

pub fn pick_list_style(_theme: &Theme, status: pick_list::Status) -> pick_list::Style {
    let border_color = match status {
        pick_list::Status::Hovered | pick_list::Status::Opened { .. } => ACCENT,
        pick_list::Status::Active => BORDER,
    };
    pick_list::Style {
        text_color: TEXT,
        placeholder_color: FAINT,
        handle_color: DIM,
        background: Background::Color(BG_SUNK),
        border: Border::default().color(border_color).width(1.0).rounded(0),
    }
}

pub fn menu_style(_theme: &Theme) -> iced::overlay::menu::Style {
    iced::overlay::menu::Style {
        background: Background::Color(BG_PANEL),
        border: Border::default().color(BORDER).width(1.0).rounded(0),
        text_color: TEXT,
        selected_text_color: ACCENT_DARK,
        selected_background: Background::Color(ACCENT),
        shadow: Shadow::default(),
    }
}

pub fn checkbox_style(_theme: &Theme, status: checkbox::Status) -> checkbox::Style {
    let (checked, enabled) = match status {
        checkbox::Status::Active { is_checked } => (is_checked, true),
        checkbox::Status::Hovered { is_checked } => (is_checked, true),
        checkbox::Status::Disabled { is_checked } => (is_checked, false),
    };
    let (background, border) = if checked {
        (ACCENT, ACCENT)
    } else if enabled {
        (BG_SUNK, BORDER)
    } else {
        (BG_RAISED, BORDER)
    };
    checkbox::Style {
        background: Background::Color(background),
        icon_color: ACCENT_DARK,
        border: Border::default().color(border).width(1.0).rounded(0),
        text_color: Some(if enabled { DIM } else { FAINT }),
    }
}

pub fn slider_style(_theme: &Theme, _status: slider::Status) -> slider::Style {
    slider::Style {
        rail: slider::Rail {
            backgrounds: (Background::Color(ACCENT), Background::Color(BG_RAISED)),
            width: 4.0,
            border: Border::default().rounded(0),
        },
        handle: slider::Handle {
            shape: slider::HandleShape::Rectangle {
                width: 10,
                border_radius: 0.0.into(),
            },
            background: Background::Color(ACCENT),
            border_width: 0.0,
            border_color: ACCENT,
        },
    }
}

pub fn scrollable_style(_theme: &Theme, _status: scrollable::Status) -> scrollable::Style {
    let rail = scrollable::Rail {
        background: Some(Background::Color(BG_PANEL)),
        border: Border::default().rounded(0),
        scroller: scrollable::Scroller {
            background: Background::Color(BORDER_HI),
            border: Border::default().rounded(0),
        },
    };
    scrollable::Style {
        container: container::Style::default(),
        vertical_rail: rail,
        horizontal_rail: rail,
        gap: None,
        auto_scroll: scrollable::AutoScroll {
            background: Background::Color(BG_PANEL),
            border: Border::default().color(BORDER).width(1.0).rounded(0),
            shadow: Shadow::default(),
            icon: DIM,
        },
    }
}

pub fn status_color(kind: Kind) -> Color {
    match kind {
        Kind::Ok => GREEN,
        Kind::Err => RED,
        Kind::Info => AMBER,
        Kind::None => DIM,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    None,
    Ok,
    Err,
    Info,
}
