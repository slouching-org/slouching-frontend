//! Native widgets composed from the supplied design board and current app state.
use crate::{
    BackendConnection, Message, Screen, Slouching, TransportState,
    file_transfer::FileAttachmentOffer, peer, storage,
};
use iced::widget::{
    self, button, canvas, column, container, image, progress_bar, row, scrollable, space, stack,
    svg, text, text_input,
};
use iced::{
    Background, Border, Color, ContentFit, Element, Fill, Font, Length, Point, Rectangle, Renderer,
    Size, Theme, font,
};
use std::collections::HashMap;
use std::sync::OnceLock;

pub const MONO: Font = Font {
    family: font::Family::Name("JetBrains Mono"),
    ..Font::DEFAULT
};
const TITLE: Font = Font {
    family: font::Family::Name("Bricolage Grotesque"),
    weight: font::Weight::ExtraBold,
    ..Font::DEFAULT
};
const NIGHT: Color = Color::from_rgb8(13, 10, 28);
const PANEL: Color = Color::from_rgb8(26, 22, 56);
const LINE: Color = Color::from_rgb8(47, 40, 88);
const PAPER: Color = Color::from_rgb8(236, 230, 255);
const GOLD: Color = Color::from_rgb8(242, 223, 138);
const VIOLET: Color = Color::from_rgb8(180, 140, 255);
const MUTED: Color = Color::from_rgb8(143, 135, 189);
const GREEN: Color = Color::from_rgb8(143, 209, 158);
const RED: Color = Color::from_rgb8(110, 33, 72);

struct Assets {
    images: HashMap<&'static str, image::Handle>,
    icons: HashMap<&'static str, svg::Handle>,
}
fn assets() -> &'static Assets {
    static ASSETS: OnceLock<Assets> = OnceLock::new();
    ASSETS.get_or_init(|| {
        macro_rules! raster { ($($name:literal => $path:literal),* $(,)?) => { HashMap::from([$(( $name, image::Handle::from_bytes(include_bytes!($path).as_slice()))),*]) }; }
        macro_rules! vector { ($($name:literal),* $(,)?) => { HashMap::from([$(( $name, svg::Handle::from_memory(include_bytes!(concat!("../assets/icons/", $name, ".svg")).as_slice()))),*]) }; }
        Assets {
            images: raster! {
                "home" => "../assets/art/bg-home.jpg",
                "wizards-cutout" => "../assets/art/wizards-cutout.png",
                "mushroom-cutout" => "../assets/art/mushroom-cutout.png",
                "mushroom-scene" => "../assets/art/scene-gnome2.jpg", "sky" => "../assets/art/sky.jpg",
                "reading" => "../assets/art/scene-reading.jpg", "orb" => "../assets/art/scene-orb.jpg",
                "frog-scene" => "../assets/art/scene-frog1.jpg", "gnome-scene" => "../assets/art/scene-gnome1.jpg",
                "frog-cutout" => "../assets/art/frog-cutout.png", "gnome-cutout" => "../assets/art/gnome-cutout.png",
                "logo" => "../assets/brand/05-two-wizards-primary-logo.png",
                "hat" => "../assets/art/appicon.jpg", "frog" => "../assets/avatars/ava-frog1.jpg",
                "gnome" => "../assets/avatars/ava-gnome1.jpg", "wizard" => "../assets/avatars/ava-pipe.jpg",
                "orb-avatar" => "../assets/avatars/ava-orb.jpg", "mushroom" => "../assets/avatars/ava-gnome2.jpg",
            },
            icons: vector! { "settings", "chat", "headphones", "users", "mic", "camera", "refresh",
                "plus", "key", "close", "check", "screen", "window", "phone", "shield", "file", "pause",
                "play", "attachment", "arrow", "mic-off", "camera-off" },
        }
    })
}

#[derive(Clone, Copy)]
struct Layout {
    x: f32,
    y: f32,
    scale: f32,
}
impl Layout {
    fn new(size: Size) -> Self {
        Self {
            x: size.width / 1280.0,
            y: size.height / 800.0,
            scale: (size.width / 1280.0).min(size.height / 800.0),
        }
    }
    fn px(self, n: f32) -> f32 {
        n * self.scale
    }
    fn label<'a>(self, value: impl Into<String>, size: f32, color: Color) -> widget::Text<'a> {
        text(value.into())
            .font(MONO)
            .size(self.px(size).max(10.0))
            .color(color)
    }
    fn title<'a>(self, value: impl Into<String>, size: f32) -> widget::Text<'a> {
        text(value.into())
            .font(TITLE)
            .size(self.px(size))
            .color(GOLD)
    }
    fn place<'a>(
        self,
        content: impl Into<Element<'a, Message>>,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
    ) -> Element<'a, Message> {
        container(container(content).width(w * self.x).height(h * self.y))
            .padding(iced::Padding {
                top: y * self.y,
                left: x * self.x,
                right: 0.0,
                bottom: 0.0,
            })
            .into()
    }
    fn icon(self, name: &'static str, color: Color, size: f32) -> Element<'static, Message> {
        svg(assets().icons[name].clone())
            .width(self.px(size))
            .height(self.px(size))
            .style(move |_, _| svg::Style { color: Some(color) })
            .into()
    }
    fn picture(self, name: &'static str, w: f32, h: f32) -> Element<'static, Message> {
        image(assets().images[name].clone())
            .width(self.px(w))
            .height(self.px(h))
            .content_fit(ContentFit::Cover)
            .into()
    }
    fn control(
        self,
        icon: &'static str,
        label: &'static str,
        msg: Option<Message>,
        primary: bool,
    ) -> Element<'static, Message> {
        let c = if primary { NIGHT } else { PAPER };
        let content = row![self.icon(icon, c, 18.0), self.label(label, 14.0, c)]
            .spacing(self.px(10.0))
            .align_y(iced::Center);
        button(container(content).center_x(Fill))
            .on_press_maybe(msg)
            .padding([self.px(14.0), self.px(18.0)])
            .width(Fill)
            .style(move |_, status| button_style(status, primary, false))
            .into()
    }
    fn nav(self, label: &'static str, msg: Message, selected: bool) -> Element<'static, Message> {
        button(self.label(label, 12.0, if selected { GOLD } else { MUTED }))
            .on_press(msg)
            .width(Fill)
            .padding([self.px(12.0), self.px(16.0)])
            .style(move |_, status| button_style(status, false, selected))
            .into()
    }
    fn icon_button(self, name: &'static str, msg: Message) -> Element<'static, Message> {
        button(self.icon(name, PAPER, 18.0))
            .on_press(msg)
            .padding(self.px(12.0))
            .style(|_, s| button_style(s, false, false))
            .into()
    }
    fn panel<'a>(self, content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
        container(content)
            .padding(self.px(22.0))
            .width(Fill)
            .height(Fill)
            .style(panel_style)
            .clip(true)
            .into()
    }
    fn input<'a>(
        self,
        placeholder: &'a str,
        value: &'a str,
        on_input: fn(String) -> Message,
    ) -> Element<'a, Message> {
        self.input_maybe(placeholder, value, Some(on_input))
    }
    fn secret_input<'a>(
        self,
        placeholder: &'a str,
        value: &'a str,
        on_input: fn(String) -> Message,
    ) -> Element<'a, Message> {
        text_input(placeholder, value)
            .on_input(on_input)
            .secure(true)
            .font(MONO)
            .size(self.px(14.0).max(11.0))
            .padding(self.px(12.0))
            .style(input_style)
            .into()
    }
    fn input_maybe<'a>(
        self,
        placeholder: &'a str,
        value: &'a str,
        on_input: Option<fn(String) -> Message>,
    ) -> Element<'a, Message> {
        text_input(placeholder, value)
            .on_input_maybe(on_input)
            .font(MONO)
            .size(self.px(14.0).max(11.0))
            .padding(self.px(12.0))
            .style(input_style)
            .into()
    }
}

fn panel_style(_: &Theme) -> container::Style {
    container::Style {
        background: Some(Color { a: 0.93, ..PANEL }.into()),
        border: Border {
            color: LINE,
            width: 1.0,
            radius: 0.0.into(),
        },
        text_color: Some(PAPER),
        ..Default::default()
    }
}
fn button_style(status: button::Status, primary: bool, selected: bool) -> button::Style {
    let disabled = status == button::Status::Disabled;
    let hovered = matches!(status, button::Status::Hovered | button::Status::Pressed);
    let bg = if primary {
        GOLD
    } else if selected || hovered {
        Color::from_rgb8(35, 28, 77)
    } else {
        Color { a: 0.87, ..NIGHT }
    };
    button::Style {
        background: Some(Background::Color(Color {
            a: if disabled { 0.5 } else { bg.a },
            ..bg
        })),
        text_color: if primary {
            NIGHT
        } else if disabled {
            MUTED
        } else {
            PAPER
        },
        border: Border {
            color: if selected || hovered { GOLD } else { LINE },
            width: if primary { 0.0 } else { 1.0 },
            radius: 0.0.into(),
        },
        ..Default::default()
    }
}
fn input_style(_: &Theme, status: text_input::Status) -> text_input::Style {
    text_input::Style {
        background: NIGHT.into(),
        border: Border {
            color: if matches!(status, text_input::Status::Focused { .. }) {
                GOLD
            } else {
                LINE
            },
            width: 1.0,
            radius: 0.0.into(),
        },
        icon: MUTED,
        placeholder: MUTED,
        value: PAPER,
        selection: VIOLET,
    }
}

pub fn view(state: &Slouching) -> Element<'_, Message> {
    widget::responsive(move |size| screen(state, Layout::new(size))).into()
}

fn screen(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let bg = if state.screen == Screen::Incoming {
        "frog-scene"
    } else {
        "home"
    };
    let shade = match state.screen {
        Screen::Home => 0.15,
        Screen::Familiar => 0.35,
        Screen::Lobby => 0.65,
        Screen::Incoming => 0.80,
        _ => 0.90,
    };
    let mut layers = vec![
        image(assets().images[bg].clone())
            .width(Fill)
            .height(Fill)
            .content_fit(ContentFit::Cover)
            .into(),
        container(space())
            .width(Fill)
            .height(Fill)
            .style(move |_| container::Style {
                background: Some(
                    iced::gradient::Linear::new(iced::Radians(std::f32::consts::FRAC_PI_2))
                        .add_stop(0.0, Color { a: shade, ..NIGHT })
                        .add_stop(
                            0.6,
                            Color {
                                a: (shade + 0.1).min(0.95),
                                ..NIGHT
                            },
                        )
                        .add_stop(1.0, Color { a: 0.90, ..NIGHT })
                        .into(),
                ),
                ..Default::default()
            })
            .into(),
    ];
    let content = match state.screen {
        Screen::Home => home(state, l),
        Screen::Familiar => familiar(state, l),
        Screen::Settings => settings(state, l),
        Screen::Call => call(state, l),
        Screen::Components => components(l),
        Screen::Lobby => lobby(l),
        Screen::Connecting => connecting(state, l),
        Screen::Share => sharing(state, l),
        Screen::Chat => chat(state, l),
        Screen::Mls => mls(state, l),
        Screen::Incoming => incoming(state, l),
        Screen::Verify => verification(state, l),
    };
    layers.push(content);
    layers.push(header(state, l));
    if state.texture {
        layers.push(canvas(Fx).width(Fill).height(Fill).into());
    }
    if state.show_gallery {
        layers.push(widget::opaque(gallery(l)));
    }
    if let Some(qr) = &state.peer_invite_qr {
        layers.push(
            container(space())
                .width(Fill)
                .height(Fill)
                .style(|_| container::Style {
                    background: Some(Color::from_rgba8(5, 4, 12, 0.82).into()),
                    ..Default::default()
                })
                .into(),
        );
        layers.push(widget::opaque(l.place(
            l.panel(
                column![
                    row![
                        l.title("Convite do dispositivo", 24.0),
                        space().width(Fill),
                        l.icon_button("close", Message::ClosePeerInviteQr)
                    ]
                    .align_y(iced::Center),
                    l.label(
                        "Capture esta tela e importe o PNG no outro dispositivo. Este convite assinado expira em 10 minutos.",
                        11.0,
                        PAPER
                    ),
                    container(image(qr.clone()).content_fit(ContentFit::Contain))
                        .width(Fill)
                        .height(l.px(320.0))
                        .center(Fill),
                    l.label(
                        "O QR contém sua chave pública e, se o listener estiver ativo, os endereços anunciados. Nunca contém chaves privadas ou token de relay.",
                        10.0,
                        MUTED
                    ),
                    l.control("close", "Fechar convite", Some(Message::ClosePeerInviteQr), false)
                ]
                .spacing(l.px(12.0)),
            ),
            390.0,
            108.0,
            500.0,
            584.0,
        )));
    }
    if let Some(note) = state.note {
        layers.push(
            l.place(
                l.panel(
                    column![
                        l.title("Ainda é uma prévia", 25.0),
                        l.label(note, 13.0, PAPER),
                        l.control("close", "Entendi", Some(Message::DismissNote), true)
                    ]
                    .spacing(l.px(16.0)),
                ),
                320.0,
                280.0,
                640.0,
                235.0,
            ),
        );
    }
    stack(layers).width(Fill).height(Fill).clip(true).into()
}

fn header(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let brand = button(
        row![
            l.picture("wizards-cutout", 38.0, 38.0),
            l.title("slouching", 26.0)
        ]
        .spacing(l.px(10.0))
        .align_y(iced::Center),
    )
    .padding(0)
    .on_press(Message::Navigate(Screen::Home))
    .style(button::text);
    let page = if matches!(state.screen, Screen::Home | Screen::Components) {
        String::new()
    } else {
        format!("/ {}", state.screen.label())
    };
    let left = row![brand, l.label(page, 12.0, MUTED)]
        .spacing(l.px(18.0))
        .align_y(iced::Center);
    let mode = if state.screen == Screen::Chat {
        "P2P · LAN/VPN"
    } else {
        "PRÉVIA VISUAL"
    };
    let right = row![
        l.label(mode, 10.0, GOLD),
        button(l.label("Telas", 11.0, PAPER))
            .on_press(Message::ToggleGallery)
            .padding(l.px(10.0))
            .style(|_, s| button_style(s, false, false)),
        l.icon_button("settings", Message::Navigate(Screen::Settings)),
        l.icon_button("chat", Message::Navigate(Screen::Chat))
    ]
    .spacing(l.px(8.0))
    .align_y(iced::Center);
    l.place(
        row![left, space().width(Fill), right].align_y(iced::Center),
        24.0,
        10.0,
        1232.0,
        46.0,
    )
}
fn gallery(l: Layout) -> Element<'static, Message> {
    let mut choices = column![
        row![
            l.label("DESIGN BOARD", 12.0, GOLD),
            space().width(Fill),
            l.icon_button("close", Message::ToggleGallery)
        ]
        .align_y(iced::Center)
    ]
    .spacing(l.px(7.0));
    for s in Screen::ALL {
        choices = choices.push(l.nav(s.label(), Message::Navigate(s), false));
    }
    choices = choices.push(l.label(
        "12 telas · chamadas de áudio em desenvolvimento\nChat texto · LAN/VPN manual",
        11.0,
        MUTED,
    ));
    l.place(l.panel(choices), 890.0, 65.0, 366.0, 700.0)
}
fn home(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let title = l.place(
        container(l.title("slouching", 120.0)).center_x(Fill),
        270.0,
        126.0,
        740.0,
        128.0,
    );
    let subtitle = l.place(
        container(
            l.label("P2P voice & video\nfor you and your crew", 20.0, PAPER)
                .align_x(iced::Center),
        )
        .center_x(Fill),
        330.0,
        254.0,
        620.0,
        74.0,
    );
    let actions = column![
        l.control(
            "headphones",
            "Join a Call",
            Some(Message::Navigate(Screen::Lobby)),
            true
        ),
        l.control(
            "users",
            "Create a Call",
            Some(Message::Navigate(Screen::Lobby)),
            false
        ),
        row![
            l.label("Have an invite link?", 12.0, PAPER),
            l.input("slouch://", &state.invite, Message::InviteChanged)
        ]
        .spacing(l.px(8.0))
        .align_y(iced::Center),
        l.label(
            "Explore a prévia · áudio direto em desenvolvimento",
            10.0,
            MUTED
        )
    ]
    .spacing(l.px(14.0));
    let features = row![
        feature(l, "arrow", "P2P", "Texto direto · experimental"),
        feature(l, "shield", "Private", "MLS · planejado"),
        feature(l, "users", "For your crew", "Voice, video, screen"),
        feature(l, "headphones", "Just vibes", "Always")
    ]
    .spacing(l.px(22.0));
    stack![
        title,
        subtitle,
        l.place(actions, 490.0, 366.0, 300.0, 225.0),
        l.place(l.panel(features), 28.0, 700.0, 1224.0, 78.0)
    ]
    .width(Fill)
    .height(Fill)
    .into()
}
fn feature(
    l: Layout,
    icon: &'static str,
    title: &'static str,
    detail: &'static str,
) -> Element<'static, Message> {
    row![
        l.icon(icon, VIOLET, 34.0),
        column![l.label(title, 13.0, PAPER), l.label(detail, 10.0, MUTED)].spacing(l.px(5.0))
    ]
    .spacing(l.px(14.0))
    .width(Fill)
    .align_y(iced::Center)
    .into()
}
fn familiar(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let mut familiars = row![].spacing(l.px(12.0));
    for (name, art) in [
        ("Sapo Mago", "frog"),
        ("Gnomo", "gnome"),
        ("Vidente do Orbe", "orb-avatar"),
    ] {
        familiars = familiars.push(
            button(
                container(
                    column![l.picture(art, 104.0, 104.0), l.label(name, 12.0, PAPER)]
                        .spacing(l.px(8.0))
                        .align_x(iced::Center),
                )
                .center_x(Fill),
            )
            .on_press(Message::ChooseFamiliar(name))
            .width(Fill)
            .padding(l.px(12.0))
            .style(move |_, s| button_style(s, false, state.familiar == name)),
        );
    }
    let has_custom_image = state.familiar_image_png.is_some();
    let custom_art: Element<'_, Message> = if let Some(png) = &state.familiar_image_png {
        image(image::Handle::from_bytes(png.clone()))
            .width(l.px(104.0))
            .height(l.px(104.0))
            .content_fit(ContentFit::Cover)
            .into()
    } else {
        container(l.icon("plus", MUTED, 34.0))
            .width(l.px(104.0))
            .height(l.px(104.0))
            .center(Fill)
            .into()
    };
    familiars = familiars.push(
        button(
            container(
                column![custom_art, l.label("Sua imagem", 12.0, PAPER)]
                    .spacing(l.px(8.0))
                    .align_x(iced::Center),
            )
            .center_x(Fill),
        )
        .width(Fill)
        .padding(l.px(12.0))
        .on_press(Message::ChooseCustomFamiliar)
        .style(move |_, s| button_style(s, has_custom_image, false)),
    );
    let progress = row![rule(GOLD, 3.0), rule(GOLD, 3.0), rule(LINE, 3.0)].spacing(l.px(6.0));
    let (profile_title, profile_detail) = match &state.profile_status {
        crate::ProfileStatus::Loading => (
            "Carregando perfil local",
            "A chave é consultada no cofre do sistema.",
        ),
        crate::ProfileStatus::Empty => (
            "Perfil local ainda não salvo",
            "O perfil fica em SQLite cifrado; a chave fica no cofre do sistema.",
        ),
        crate::ProfileStatus::Saved => (
            "Perfil salvo localmente · cifrado",
            "Nome e familiar não são uma identidade criptográfica.",
        ),
        crate::ProfileStatus::Saving => (
            "Salvando perfil local...",
            "A chave e os dados ficam neste dispositivo.",
        ),
        crate::ProfileStatus::Failed => (
            "Cofre ou banco local indisponível",
            "Ative o cofre de senhas do sistema e tente de novo. Não salvamos em texto puro.",
        ),
    };
    let (identity_title, identity_detail) = match &state.identity_status {
        crate::IdentityStatus::Loading => (
            "Carregando identidade do dispositivo",
            "A chave é consultada no cofre do sistema.".to_owned(),
        ),
        crate::IdentityStatus::Missing => (
            "Identidade Ed25519 ainda não criada",
            "Crie a chave privada local no cofre do sistema.".to_owned(),
        ),
        crate::IdentityStatus::Creating => (
            "Criando identidade do dispositivo...",
            "A chave privada será guardada no cofre do sistema.".to_owned(),
        ),
        crate::IdentityStatus::Ready(public_key) => (
            "Chave pública Ed25519 · não verificada",
            public_key
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ),
        crate::IdentityStatus::Failed => (
            "Identidade local indisponível",
            "Não foi possível ler a chave no cofre. Confira o serviço e tente novamente."
                .to_owned(),
        ),
    };
    let identity_action = match state.identity_status {
        crate::IdentityStatus::Loading => "Carregando chave...",
        crate::IdentityStatus::Creating => "Criando chave...",
        crate::IdentityStatus::Ready(_) => "Identidade criada",
        crate::IdentityStatus::Missing => "Criar identidade",
        crate::IdentityStatus::Failed => "Tentar novamente",
    };
    let identity_message = match state.identity_status {
        crate::IdentityStatus::Missing | crate::IdentityStatus::Failed => {
            Some(Message::CreateIdentity)
        }
        _ => None,
    };
    let key = container(
        row![
            l.icon("key", VIOLET, 24.0),
            column![
                l.label(profile_title, 13.0, PAPER),
                l.label(profile_detail, 11.0, MUTED)
            ]
            .spacing(l.px(5.0))
            .width(Fill),
            l.icon("shield", VIOLET, 24.0),
            column![
                l.label(identity_title, 13.0, PAPER),
                l.label(identity_detail, 11.0, MUTED)
            ]
            .spacing(l.px(5.0))
            .width(Fill)
        ]
        .spacing(l.px(12.0))
        .align_y(iced::Center),
    )
    .width(Fill)
    .padding(l.px(16.0))
    .style(|_| container::Style {
        background: Some(NIGHT.into()),
        border: Border {
            color: LINE,
            width: 1.0,
            ..Default::default()
        },
        ..Default::default()
    });
    let body = column![
        progress,
        l.title("Quem senta na fogueira?", 40.0),
        l.label(
            "Sem conta, sem e-mail. Comece escolhendo seu nome e familiar.",
            13.0,
            PAPER
        ),
        column![
            l.label("N O M E  N A  R O D A", 10.0, MUTED),
            l.input("Como podemos te chamar?", &state.name, Message::NameChanged)
        ]
        .spacing(l.px(8.0)),
        column![
            l.label("E S C O L H A  S E U  F A M I L I A R", 10.0, MUTED),
            familiars
        ]
        .spacing(l.px(10.0)),
        key,
        row![
            l.control(
                "close",
                "Voltar",
                Some(Message::Navigate(Screen::Home)),
                false
            ),
            l.control("check", "Salvar perfil", Some(Message::SaveProfile), false),
            l.control("key", identity_action, identity_message, true)
        ]
        .spacing(l.px(8.0))
    ]
    .spacing(l.px(19.0));
    l.place(l.panel(body), 230.0, 92.0, 820.0, 620.0)
}
fn rule(color: Color, height: f32) -> Element<'static, Message> {
    container(space())
        .width(Fill)
        .height(height)
        .style(move |_| container::Style {
            background: Some(color.into()),
            ..Default::default()
        })
        .into()
}
fn tile(l: Layout, art: &'static str, label: impl Into<String>) -> Element<'static, Message> {
    let overlay = container(l.label(label, 11.0, PAPER))
        .padding(l.px(10.0))
        .style(|_| container::Style {
            background: Some(Color { a: 0.8, ..NIGHT }.into()),
            ..Default::default()
        });
    stack![
        image(assets().images[art].clone())
            .content_fit(ContentFit::Cover)
            .width(Fill)
            .height(Fill),
        container(overlay).align_bottom(Fill)
    ]
    .width(Fill)
    .height(Fill)
    .into()
}
fn boxed<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content)
        .width(Fill)
        .height(Fill)
        .style(panel_style)
        .clip(true)
        .into()
}
fn settings(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let mut tabs = column![].spacing(l.px(6.0));
    for (i, label) in [
        "Perfil & familiar",
        "Áudio & vídeo",
        "Rede & P2P",
        "Chaves & MLS",
        "Dispositivos",
        "Notificações",
        "Aparência",
        "Atalhos",
    ]
    .into_iter()
    .enumerate()
    {
        tabs = tabs.push(l.nav(
            label,
            Message::SettingsTab(i as u8),
            state.settings_tab == i as u8,
        ));
    }
    let body: Element<'_, Message> = match state.settings_tab {
        1 => {
            let mut input_choices = column![].spacing(l.px(4.0));
            for device in &state.audio_input_devices {
                let selected = state.audio_input_selected.as_ref() == Some(&device.id);
                input_choices = input_choices.push(
                    button(l.label(device.name.clone(), 11.0, PAPER))
                        .on_press(Message::AudioInputSelected(device.id.clone()))
                        .padding([l.px(5.0), l.px(8.0)])
                        .width(Fill)
                        .style(move |_, status| button_style(status, selected, false)),
                );
            }
            if state.audio_input_devices.is_empty() {
                input_choices = input_choices.push(l.label("Nenhuma entrada de áudio", 11.0, MUTED));
            }
            let monitor_active = state.audio_monitor_handle.is_some();
            let monitor_button = button(l.label(
                if monitor_active {
                    "Parar teste do microfone"
                } else {
                    "Testar microfone localmente"
                },
                11.0,
                if monitor_active { NIGHT } else { PAPER },
            ))
            .on_press_maybe(
                (monitor_active || state.audio_input_selected.is_some()).then_some(if monitor_active {
                    Message::StopAudioMonitor
                } else {
                    Message::StartAudioMonitor
                }),
            )
            .padding([l.px(7.0), l.px(10.0)])
            .style(move |_, status| button_style(status, monitor_active, false));
            let mut output_choices = column![].spacing(l.px(4.0));
            for device in &state.audio_output_devices {
                let selected = state.audio_output_selected.as_ref() == Some(&device.id);
                output_choices = output_choices.push(
                    button(l.label(device.name.clone(), 11.0, PAPER))
                        .on_press(Message::AudioOutputSelected(device.id.clone()))
                        .padding([l.px(5.0), l.px(8.0)])
                        .width(Fill)
                        .style(move |_, status| button_style(status, selected, false)),
                );
            }
            if state.audio_output_devices.is_empty() {
                output_choices = output_choices.push(l.label("Nenhuma saída de áudio", 11.0, MUTED));
            }
            let mut audio = column![
                l.label("Á U D I O", 11.0, GOLD),
                l.label("Microfone", 13.0, PAPER),
                container(scrollable(input_choices).height(l.px(54.0))).height(l.px(58.0)),
                row![
                    monitor_button,
                    container(progress_bar(0.0..=1.0, state.audio_monitor_level)).width(Fill),
                    l.label(format!("{:>3.0}%", state.audio_monitor_level * 100.0), 10.0, GOLD)
                ]
                .spacing(l.px(8.0))
                .align_y(iced::Center),
                l.label("Saída", 13.0, PAPER),
                container(scrollable(output_choices).height(l.px(54.0))).height(l.px(58.0)),
                button(l.label("Atualizar dispositivos", 11.0, PAPER))
                    .on_press(Message::RefreshAudioDevices)
                    .padding([l.px(7.0), l.px(10.0)])
                    .style(|_, status| button_style(status, false, false)),
                l.label(state.audio_devices_status.clone(), 10.0, MUTED),
                option(l, "Supressão de ruído (RNNoise)", false),
                option(l, "Cancelamento de eco", false),
                option(l, "Push-to-talk", false)
            ]
            .spacing(l.px(7.0));
            if state.pending_call_offer.is_some() {
                audio = audio.push(l.control(
                    "phone",
                    "Voltar à chamada recebida",
                    Some(Message::Navigate(Screen::Incoming)),
                    true,
                ));
            }
            let mut camera_choices = column![].spacing(l.px(4.0));
            for device in &state.camera_sources {
                let id = device.id.clone();
                let selected = state.selected_camera.as_ref() == Some(&id);
                camera_choices = camera_choices.push(
                    button(l.label(format!("{} · {}", device.name, id), 11.0, PAPER))
                        .on_press(Message::SelectCamera(id))
                        .padding([l.px(5.0), l.px(8.0)])
                        .width(Fill)
                        .style(move |_, status| button_style(status, selected, false)),
                );
            }
            if state.camera_sources.is_empty() {
                camera_choices = camera_choices.push(l.label(
                    "Nenhuma câmera enumerada. Atualize a lista.",
                    11.0,
                    MUTED,
                ));
            }
            let camera_preview: Element<'_, Message> = if let Some(handle) = state.camera_preview.clone() {
                image(handle)
                    .content_fit(ContentFit::Contain)
                    .width(Fill)
                    .height(l.px(150.0))
                    .into()
            } else {
                container(tile(l, "reading", "PRÉVIA LOCAL · câmera fechada"))
                    .height(l.px(150.0))
                    .into()
            };
            let video = column![
                l.label("V Í D E O", 11.0, GOLD),
                camera_preview,
                l.label("Câmera · prévia local não é enviada", 12.0, PAPER),
                container(scrollable(camera_choices).height(l.px(70.0))).height(l.px(74.0)),
                row![
                    button(l.label("Atualizar câmeras", 11.0, PAPER))
                        .on_press(Message::RefreshCameras)
                        .padding([l.px(7.0), l.px(10.0)])
                        .style(|_, status| button_style(status, false, false)),
                    button(l.label("Prévia local", 11.0, PAPER))
                        .on_press_maybe(state.selected_camera.clone().map(Message::CaptureCamera))
                        .padding([l.px(7.0), l.px(10.0)])
                        .style(|_, status| button_style(status, false, false)),
                ]
                .spacing(l.px(8.0)),
                l.label(state.screen_capture_status.clone(), 10.0, MUTED),
                option(l, "Filtro VHS na câmera", false)
            ]
            .spacing(l.px(8.0));
            let topology = row![
                column![l.label("T O P O L O G I A", 11.0, GOLD),
                    l.label("Rotas diretas quando possíveis; relay ou SFU opcional operado por um membro.", 12.0, PAPER),
                    l.label("Sem limite de mesh medido", 11.0, MUTED)].spacing(l.px(16.0)).width(Fill),
                column![l.label("PRIVACIDADE DE IP", 11.0, GOLD), option(l,"Só via relay",false),
                    l.label("Nenhuma rota configurada.", 11.0, MUTED)].spacing(l.px(16.0)).width(Fill),
                column![l.label("SERVIÇOS", 11.0, GOLD),l.label("STUN · não configurado",12.0,MUTED),
                    l.label("TURN · não configurado",12.0,MUTED),l.label("SFU · não configurado",12.0,MUTED)].spacing(l.px(16.0)).width(Fill)
            ].spacing(l.px(22.0));
            column![
                row![l.panel(audio), l.panel(video)]
                    .spacing(l.px(18.0))
                    .height(l.px(440.0)),
                l.panel(topology)
            ]
            .spacing(l.px(18.0))
            .into()
        }
        0 => {
            let avatar: Element<'_, Message> = if let Some(png) = &state.familiar_image_png {
                image(image::Handle::from_bytes(png.clone()))
                    .width(l.px(100.0))
                    .height(l.px(100.0))
                    .content_fit(ContentFit::Cover)
                    .into()
            } else {
                let art = match state.familiar {
                    "Gnomo" => "gnome",
                    "Vidente do Orbe" => "orb-avatar",
                    _ => "frog",
                };
                l.picture(art, 100.0, 100.0)
            };
            l.panel(column![
                l.title("Perfil & familiar", 34.0),
                row![
                    avatar,
                    column![
                        l.label(
                            if state.name.is_empty() {
                                "Seu nome"
                            } else {
                                &state.name
                            },
                            18.0,
                            PAPER
                        ),
                        l.label(state.familiar, 13.0, VIOLET)
                    ]
                    .spacing(l.px(10.0))
                ]
                .spacing(l.px(20.0)),
                l.label(
                    "Perfil de prévia · sem identidade criptográfica",
                    12.0,
                    MUTED
                ),
                l.control(
                    "users",
                    "Escolher familiar",
                    Some(Message::Navigate(Screen::Familiar)),
                    true
                )
            ]
            .spacing(l.px(24.0)))
        }
        2 => l.panel(
            column![
                l.title("Rede & P2P", 34.0),
                l.label(
                    "O diagnóstico HTTP/WebSocket abaixo verifica apenas o backend local.",
                    12.0,
                    MUTED
                ),
                diagnostics(state, l),
                l.control(
                    "refresh",
                    "Atualizar diagnóstico local",
                    Some(Message::RefreshBackend),
                    false
                ),
                l.label(
                    "Mensagens diretas usam Rust/Iroh; LAN ou VPN precisa permitir tráfego UDP.",
                    12.0,
                    PAPER
                ),
                l.control(
                    "chat",
                    "Abrir mensagens diretas LAN",
                    Some(Message::Navigate(Screen::Chat)),
                    true
                ),
                rule(LINE, l.px(8.0)),
                l.label("CÓPIAS MLS DELEGADAS", 11.0, GOLD),
                l.label(
                    "Permite que este dispositivo guarde temporariamente ciphertext MLS autorizado por outro membro. O conteúdo permanece criptografado.",
                    12.0,
                    PAPER
                ),
                l.label(
                    if state.delegated_mls_storage.is_some_and(|status| status.enabled) {
                        "Com opt-in ativo, o listener aceita cópias assinadas de vários peers; texto e outros quadros continuam exigindo o peer fixado."
                    } else {
                        "Ative antes de iniciar o listener para aceitar cópias de membros sem trocar a chave fixada para o chat."
                    },
                    11.0,
                    MUTED
                ),
                l.label(
                    match state.delegated_mls_storage {
                        Some(status) if status.enabled => "Armazenamento ativado · limite de 64 MiB",
                        Some(_) => "Armazenamento desativado · nenhuma cópia é retida",
                        None => "Carregando política local de armazenamento…",
                    },
                    11.0,
                    if state.delegated_mls_storage.is_some_and(|status| status.enabled) { GREEN } else { MUTED }
                ),
                l.control(
                    "shield",
                    if state.delegated_mls_storage.is_some_and(|status| status.enabled) {
                        "Desativar cópias MLS neste dispositivo"
                    } else {
                        "Permitir cópias MLS neste dispositivo"
                    },
                    state.delegated_mls_storage.map(|status| Message::SetDelegatedMlsStorage(!status.enabled)),
                    state.delegated_mls_storage.is_some()
                ),
                if let Some(error) = &state.delegated_mls_storage_error {
                    l.label(error, 11.0, RED)
                } else {
                    l.label("A fila expira em até 30 dias e é apagada após a confirmação do destinatário.", 11.0, MUTED)
                }
            ]
            .spacing(l.px(24.0)),
        ),
        3 => l.panel(
            column![
                l.title("Chaves & MLS", 34.0),
                l.label(
                    "Nenhuma chave local, grupo MLS ou fingerprint criado.",
                    13.0,
                    PAPER
                ),
                l.control(
                    "shield",
                    "Ver prévia do selo",
                    Some(Message::Navigate(Screen::Verify)),
                    false
                )
            ]
            .spacing(l.px(24.0)),
        ),
        6 => l.panel(
            column![
                l.title("Aparência", 34.0),
                l.label("Textura VHS na interface", 14.0, PAPER),
                l.control(
                    "screen",
                    if state.texture {
                        "Desativar scanlines"
                    } else {
                        "Ativar scanlines"
                    },
                    Some(Message::ToggleTexture),
                    true
                ),
                l.label(
                    "Este ajuste afeta somente a interface. Nenhuma câmera é capturada.",
                    12.0,
                    MUTED
                )
            ]
            .spacing(l.px(24.0)),
        ),
        _ => l.panel(
            column![
                l.title(Screen::Settings.label(), 34.0),
                l.label(
                    "Esta seção ainda não tem integração funcional.",
                    14.0,
                    PAPER
                ),
                l.label(
                    "Use as telas de prévia para explorar a direção visual.",
                    12.0,
                    MUTED
                )
            ]
            .spacing(l.px(24.0)),
        ),
    };
    stack![
        l.place(l.panel(tabs), 24.0, 82.0, 220.0, 665.0),
        l.place(body, 262.0, 82.0, 994.0, 665.0)
    ]
    .width(Fill)
    .height(Fill)
    .into()
}
fn field(l: Layout, label: &str) -> Element<'static, Message> {
    container(l.label(label, 12.0, PAPER))
        .padding(l.px(12.0))
        .width(Fill)
        .style(|_| container::Style {
            background: Some(NIGHT.into()),
            border: Border {
                color: LINE,
                width: 1.0,
                ..Default::default()
            },
            ..Default::default()
        })
        .into()
}
fn option(l: Layout, label: &str, on: bool) -> Element<'static, Message> {
    row![
        container(space())
            .width(l.px(15.0))
            .height(l.px(15.0))
            .style(move |_| container::Style {
                background: Some(if on { GOLD } else { NIGHT }.into()),
                border: Border {
                    color: LINE,
                    width: 1.0,
                    ..Default::default()
                },
                ..Default::default()
            }),
        l.label(label, 12.0, MUTED)
    ]
    .spacing(l.px(10.0))
    .align_y(iced::Center)
    .into()
}
fn diagnostics(state: &Slouching, l: Layout) -> Element<'static, Message> {
    let http = match &state.backend {
        BackendConnection::Connecting => "Consultando servidor local…".into(),
        BackendConnection::Unavailable(reason) => format!("Servidor local indisponível: {reason}"),
        BackendConnection::ContractMismatch(reason) => format!("Contrato incompatível: {reason}"),
        BackendConnection::Connected(s) => format!(
            "Elixir local · contrato v{} · {} peers\nIdentidade: {:?} · mensagens: {:?} · chamadas: {:?}",
            s.contract_version, s.peer_connections, s.identity, s.messaging, s.calls
        ),
    };
    let ws = match &state.transport {
        TransportState::Connecting(attempt) => format!("WebSocket · tentativa {attempt}"),
        TransportState::Disconnected {
            reason,
            retry_seconds,
        } => format!("Transporte desconectado · nova tentativa em {retry_seconds}s\n{reason}"),
        TransportState::ProtocolError(reason) => format!("Erro de protocolo: {reason}"),
        TransportState::Active { hello, heartbeats } => format!(
            "Transporte local ativo · v{} · {heartbeats} Pongs\nIdentidade: {} · mensagens: {} · chamadas: {}",
            hello.protocol_version,
            hello.identity_available,
            hello.messaging_available,
            hello.calls_available
        ),
    };
    column![l.label(http, 12.0, PAPER), l.label(ws, 12.0, VIOLET)]
        .spacing(l.px(18.0))
        .into()
}
fn call(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let stage: Element<'_, Message> = if let Some(frame) = state.remote_screen_frame.clone() {
        container(
            image(frame)
                .content_fit(ContentFit::Contain)
                .width(Fill)
                .height(Fill),
        )
        .width(Fill)
        .height(Fill)
        .style(panel_style)
        .into()
    } else {
        tile(
            l,
            "orb",
            "Bram · cena ilustrativa / nenhuma câmera conectada",
        )
    };
    let filmstrip = row![
        boxed(tile(l, "frog-scene", "Mara · personagem")),
        boxed(tile(l, "gnome-scene", "Pim · personagem")),
        boxed(tile(l, "hat", "Você · câmera indisponível"))
    ]
    .spacing(l.px(12.0));
    let video_control: Element<'_, Message> = if state.screen_sharing_active {
        l.control(
            "close",
            "Parar compartilhamento",
            Some(Message::StopScreenShare),
            false,
        )
    } else {
        l.icon_button("camera", Message::OpenCameraShare)
    };
    let controls = row![
        l.control(
            if state.call_mic_muted {
                "mic-off"
            } else {
                "mic"
            },
            if state.call_mic_muted {
                "Ativar microfone"
            } else {
                "Silenciar microfone"
            },
            state
                .call_rtc_session
                .is_some()
                .then_some(Message::ToggleCallMic),
            state.call_rtc_session.is_some()
        ),
        video_control,
        l.icon_button("screen", Message::OpenScreenShare),
        button(l.label("Leave", 14.0, PAPER))
            .on_press(if state.call_rtc_session.is_some() {
                Message::EndCall
            } else {
                Message::Navigate(Screen::Home)
            })
            .padding([l.px(14.0), l.px(30.0)])
            .style(|_, _| button::Style {
                background: Some(RED.into()),
                text_color: PAPER,
                ..Default::default()
            })
    ]
    .spacing(l.px(10.0));
    let roster = column![
        l.label("I N  T H E  R O O M", 11.0, MUTED),
        person(l, "orb-avatar", "Bram", "exemplo"),
        person(l, "frog", "Mara", "exemplo"),
        person(l, "gnome", "Pim", "exemplo"),
        person(l, "wizard", "You", "prévia")
    ]
    .spacing(l.px(13.0));
    let room_messages: Element<'_, Message> = if state.call_room_messages.is_empty() {
        column![l.label(
            "As mensagens desta chamada ficam só na memória e desaparecem ao sair.",
            10.0,
            MUTED
        )]
        .into()
    } else {
        let entries = state
            .call_room_messages
            .iter()
            .map(|message| -> Element<'_, Message> {
                let author = if message.local { "Você" } else { "Peer" };
                let color = if message.local { GOLD } else { VIOLET };
                let bubble = container(
                    column![
                        l.label(author, 9.0, color),
                        l.label(message.text.clone(), 11.0, PAPER)
                    ]
                    .spacing(l.px(3.0)),
                )
                .padding(l.px(8.0))
                .style(panel_style);
                if message.local {
                    row![space().width(Fill), bubble].into()
                } else {
                    row![bubble, space().width(Fill)].into()
                }
            });
        column(entries).spacing(l.px(6.0)).into()
    };
    let call_chat_composer = row![
        l.input(
            "Mensagem temporária",
            &state.call_room_draft,
            Message::RoomChatDraftChanged
        ),
        l.control(
            "arrow",
            "Enviar",
            Some(Message::SendRoomChat),
            state.call_rtc_session.is_none() || state.call_room_draft.trim().is_empty()
        )
    ]
    .spacing(l.px(6.0));
    let identity_ready = matches!(state.identity_status, crate::IdentityStatus::Ready(_));
    let call_group_controls: Element<'_, Message> = if state.call_group_id.is_empty() {
        column![
            l.label("Nenhum grupo MLS de chamada neste perfil.", 10.0, MUTED),
            l.control(
                "users",
                "Criar grupo protegido",
                Some(Message::CreateCallMlsGroup),
                identity_ready && !state.call_group_creating
            )
        ]
        .spacing(l.px(7.0))
        .into()
    } else {
        let group_id = &state.call_group_id;
        column![
            l.label(
                format!("ID {}…", &group_id[..group_id.len().min(16)]),
                10.0,
                PAPER
            ),
            l.control(
                "key",
                "Copiar ID",
                Some(Message::CopyMlsValue(state.call_group_id.clone())),
                false
            ),
            l.control(
                "users",
                "Convidar participantes",
                Some(Message::OpenCallMlsGroup),
                true
            ),
            l.control(
                "headphones",
                if state.call_rtc_session.is_some() {
                    "Encerrar chamada"
                } else {
                    "Negociar WebRTC"
                },
                Some(if state.call_rtc_session.is_some() {
                    Message::EndCall
                } else {
                    Message::StartCall
                }),
                state.call_rtc_session.is_some() || state.active_peer_device.is_some()
            ),
            l.control(
                "plus",
                "Preparar outra chamada",
                Some(Message::CreateCallMlsGroup),
                identity_ready && !state.call_group_creating
            )
        ]
        .spacing(l.px(5.0))
        .into()
    };
    let share_status: Element<'_, Message> = if state.screen_sharing_active {
        l.label(state.screen_share_status.clone(), 9.0, GREEN)
            .into()
    } else {
        space().height(l.px(0.0)).into()
    };
    let camp = column![
        l.label("GRUPO MLS DA CHAMADA", 11.0, GOLD),
        call_group_controls,
        l.label(&state.call_group_status, 10.0, MUTED),
        l.label(
            if state.call_rtc_session.is_some() {
                "WEBRTC · voz, chat temporário e vídeo protegido"
            } else {
                "ÁUDIO · Opus/SFrame · grupo MLS dedicado"
            },
            9.0,
            VIOLET
        ),
        share_status,
        rule(LINE, 1.0),
        l.label("CHAT TEMPORÁRIO · SÓ ESTA CHAMADA", 10.0, MUTED),
        scrollable(room_messages).height(l.px(155.0)),
        call_chat_composer
    ]
    .spacing(l.px(8.0));
    stack![
        l.place(boxed(stage), 22.0, 70.0, 920.0, 426.0),
        l.place(filmstrip, 22.0, 510.0, 920.0, 164.0),
        l.place(container(controls).center_x(Fill), 22.0, 690.0, 920.0, 56.0),
        l.place(l.panel(roster), 962.0, 70.0, 296.0, 204.0),
        l.place(l.panel(camp), 962.0, 290.0, 296.0, 456.0)
    ]
    .width(Fill)
    .height(Fill)
    .into()
}
fn person(l: Layout, art: &'static str, name: &str, status: &str) -> Element<'static, Message> {
    row![
        l.picture(art, 28.0, 28.0),
        l.label(name, 12.0, PAPER),
        space().width(Fill),
        l.label(status, 11.0, MUTED)
    ]
    .spacing(l.px(12.0))
    .align_y(iced::Center)
    .into()
}
fn lobby(l: Layout) -> Element<'static, Message> {
    let stage = tile(l, "reading", "ILUSTRAÇÃO · sem captura local");
    let details = column![
        l.label("N O V A  F O G U E I R A", 10.0, MUTED),
        l.title("the-mossy-stump", 32.0),
        l.label("CONVITE", 11.0, GOLD),
        field(l, "Nenhum convite gerado"),
        l.label(
            "O grupo e suas chaves ainda não existem. Nenhum participante entrou.",
            12.0,
            MUTED
        ),
        l.label("PERSONAGENS DA PRÉVIA", 11.0, GOLD),
        person(l, "frog", "Mara", "ilustração"),
        person(l, "gnome", "Pim", "ilustração"),
        option(l, "Entrar mutado", true),
        l.control(
            "headphones",
            "Explorar a tela de conexão",
            Some(Message::Navigate(Screen::Connecting)),
            true
        )
    ]
    .spacing(l.px(20.0));
    let controls = row![
        l.icon_button(
            "mic",
            Message::PreviewAction("Esta imagem é ilustrativa. O microfone não foi aberto.")
        ),
        l.icon_button(
            "camera",
            Message::PreviewAction("Esta imagem é ilustrativa. A câmera não foi aberta.")
        ),
        l.icon_button("settings", Message::Navigate(Screen::Settings))
    ]
    .spacing(l.px(10.0));
    stack![
        l.place(boxed(stage), 42.0, 116.0, 748.0, 446.0),
        l.place(container(controls).center_x(Fill), 42.0, 580.0, 748.0, 58.0),
        l.place(l.panel(details), 814.0, 116.0, 422.0, 544.0)
    ]
    .width(Fill)
    .height(Fill)
    .into()
}
fn connecting(state: &Slouching, l: Layout) -> Element<'static, Message> {
    let identity = match &state.identity_status {
        crate::IdentityStatus::Loading => "Carregando identidade do dispositivo…".to_owned(),
        crate::IdentityStatus::Missing => {
            "Identidade ainda não criada neste dispositivo.".to_owned()
        }
        crate::IdentityStatus::Creating => "Criando identidade local…".to_owned(),
        crate::IdentityStatus::Ready(key) => format!(
            "Identidade local pronta · {}…{}",
            hex::encode(&key[..4]),
            hex::encode(&key[28..])
        ),
        crate::IdentityStatus::Failed => "Não foi possível carregar a identidade local.".to_owned(),
    };
    let listener = match &state.peer_listen_status {
        crate::PeerListenStatus::Idle => "Listener P2P parado.".to_owned(),
        crate::PeerListenStatus::Starting { port } => {
            format!("Abrindo listener UDP na porta {port}…")
        }
        crate::PeerListenStatus::Listening { port, addresses } => {
            let routes = addresses
                .iter()
                .filter(|address| !address.ip().is_unspecified() && !address.ip().is_loopback())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if routes.is_empty() {
                format!("Listener UDP {port} ativo, mas nenhuma rota LAN/VPN foi anunciada.")
            } else {
                format!(
                    "Listener UDP ativo · compartilhe uma rota alcançável: {}",
                    routes.join(" · ")
                )
            }
        }
        crate::PeerListenStatus::Connected => {
            "Sessão QUIC autenticada com o peer pinado.".to_owned()
        }
        crate::PeerListenStatus::Disconnected(reason) => format!("Sessão P2P encerrada: {reason}"),
        crate::PeerListenStatus::Unauthorized(reason) => format!("Peer recusado: {reason}"),
        crate::PeerListenStatus::Failed(reason) => format!("Listener P2P falhou: {reason}"),
    };
    let sending = match &state.peer_send_status {
        crate::PeerSendStatus::Idle => "Nenhum envio P2P em andamento.".to_owned(),
        crate::PeerSendStatus::Connecting => {
            "Tentando abrir uma rota QUIC direta ou relay configurado…".to_owned()
        }
        crate::PeerSendStatus::AwaitingAck => {
            "Conectado; aguardando ACK de persistência do peer.".to_owned()
        }
        crate::PeerSendStatus::Sent => {
            "Mensagem aceita pelo peer e salva no histórico local.".to_owned()
        }
        crate::PeerSendStatus::Failed(reason) => format!("Envio não confirmado: {reason}"),
    };
    let call = match &state.call_rtc_session {
        Some(session) => format!("WebRTC · {}", *session.connection_state().borrow()),
        None => state.call_group_status.clone(),
    };
    let status = column![
        l.label("ESTADO REAL DESTE DISPOSITIVO", 10.0, GOLD),
        l.label(identity, 12.0, PAPER),
        rule(LINE, l.px(1.0)),
        l.label("P2P · QUIC", 10.0, GOLD),
        l.label(listener, 12.0, PAPER),
        l.label(sending, 12.0, MUTED),
        rule(LINE, l.px(1.0)),
        l.label("CHAMADA · WEBRTC", 10.0, GOLD),
        l.label(call, 12.0, PAPER),
        l.label("QUIC/relay de mensagens não é TURN. Chamadas usam candidatos ICE host; TURN e SFU ainda não estão configurados.", 11.0, MUTED),
        rule(LINE, l.px(1.0)),
        l.label("SERVIÇOS LOCAIS · ELIXIR", 10.0, GOLD),
        boxed(diagnostics(state, l)),
    ].spacing(l.px(12.0));
    let actions = column![
        l.label("ABRIR UM FLUXO FUNCIONAL", 10.0, GOLD),
        l.control("chat", "Texto direto · LAN/VPN", Some(Message::Navigate(Screen::Chat)), true),
        l.control("users", "Grupo MLS", Some(Message::Navigate(Screen::Mls)), false),
        l.control("headphones", "Chamada", Some(Message::Navigate(Screen::Call)), false),
        l.control("settings", "Rede & P2P", Some(Message::OpenNetworkSettings), false),
        l.label("VPN entre máquinas e chamadas em redes diferentes ainda precisam de validação física. Sem rota alcançável, a mensagem não é enviada.", 11.0, MUTED),
    ].spacing(l.px(14.0));
    stack![
        l.place(l.title("Conexão & rotas", 32.0), 42.0, 30.0, 600.0, 52.0),
        l.place(l.panel(status), 32.0, 94.0, 755.0, 654.0),
        l.place(l.panel(actions), 810.0, 94.0, 438.0, 654.0),
    ]
    .width(Fill)
    .height(Fill)
    .into()
}

fn sharing(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let tabs = row![
        l.nav("Telas", Message::ShareTab(0), state.share_tab == 0),
        l.nav("Janelas", Message::ShareTab(1), state.share_tab == 1),
        l.nav("Câmera", Message::ShareTab(2), state.share_tab == 2)
    ]
    .spacing(l.px(8.0));
    let mut sources = column![].spacing(l.px(8.0));
    for source in &state.screen_sources {
        let id = source.id;
        let selected = state.selected_source == Some(id);
        sources = sources.push(
            button(
                row![
                    l.label(
                        format!("{} · {} × {}", source.name, source.width, source.height),
                        13.0,
                        PAPER
                    ),
                    space().width(Fill),
                    l.label(
                        if selected {
                            "SELECIONADA"
                        } else {
                            "Selecionar"
                        },
                        10.0,
                        if selected { GOLD } else { MUTED }
                    )
                ]
                .align_y(iced::Alignment::Center)
                .spacing(l.px(10.0)),
            )
            .width(Fill)
            .padding(l.px(12.0))
            .on_press(Message::SelectScreen(id))
            .style(move |_, s| button_style(s, false, selected)),
        );
    }
    let mut windows = column![].spacing(l.px(8.0));
    for source in &state.window_sources {
        let id = source.id;
        let selected = state.selected_window == Some(id);
        windows = windows.push(
            button(
                row![
                    l.label(
                        format!("{} · {} × {}", source.name, source.width, source.height),
                        13.0,
                        PAPER
                    ),
                    space().width(Fill),
                    l.label(
                        if selected {
                            "SELECIONADA"
                        } else {
                            "Selecionar"
                        },
                        10.0,
                        if selected { GOLD } else { MUTED }
                    )
                ]
                .align_y(iced::Alignment::Center)
                .spacing(l.px(10.0)),
            )
            .width(Fill)
            .padding(l.px(12.0))
            .on_press(Message::SelectWindow(id))
            .style(move |_, status| button_style(status, false, selected)),
        );
    }
    let mut cameras = column![].spacing(l.px(8.0));
    for source in &state.camera_sources {
        let id = source.id.clone();
        let selected = state.selected_camera.as_ref() == Some(&id);
        cameras = cameras.push(
            button(
                row![
                    l.label(format!("{} · {}", source.name, id), 13.0, PAPER),
                    space().width(Fill),
                    l.label(
                        if selected {
                            "SELECIONADA"
                        } else {
                            "Selecionar"
                        },
                        10.0,
                        if selected { GOLD } else { MUTED }
                    )
                ]
                .align_y(iced::Alignment::Center)
                .spacing(l.px(10.0)),
            )
            .width(Fill)
            .padding(l.px(12.0))
            .on_press(Message::SelectCamera(id))
            .style(move |_, s| button_style(s, false, selected)),
        );
    }
    let preview_handle = match state.share_tab {
        1 => state.window_preview.clone(),
        2 => state.camera_preview.clone(),
        _ => state.screen_preview.clone(),
    };
    let preview: Element<'_, Message> = if let Some(handle) = preview_handle {
        image(handle)
            .content_fit(ContentFit::Contain)
            .width(Fill)
            .height(l.px(290.0))
            .into()
    } else {
        container(l.label(
            match state.share_tab {
                1 => "A prévia da janela aparecerá aqui após sua captura.",
                2 => "A prévia da câmera aparecerá aqui após sua captura.",
                _ => "A prévia da tela aparecerá aqui após sua captura.",
            },
            12.0,
            MUTED,
        ))
        .width(Fill)
        .height(l.px(290.0))
        .center_x(Fill)
        .center_y(Fill)
        .style(panel_style)
        .into()
    };
    let source_list: Element<'_, Message> = if state.share_tab == 0 {
        if state.screen_sources.is_empty() {
            l.label("Nenhuma tela enumerada. Use Atualizar telas ou confira a permissão de captura do ambiente gráfico.", 12.0, MUTED).into()
        } else {
            sources.into()
        }
    } else if state.share_tab == 1 {
        if state.window_sources.is_empty() {
            if crate::screen_capture::uses_wayland_window_portal() {
                l.label(
                    "Wayland: o seletor do desktop escolhe a janela e solicita permissão quando você captura a prévia ou compartilha.",
                    12.0,
                    MUTED,
                )
                .into()
            } else {
                l.label(
                    "Nenhuma janela capturável foi encontrada. Confira o ambiente gráfico e as permissões.",
                    12.0,
                    MUTED,
                )
                .into()
            }
        } else {
            windows.into()
        }
    } else if state.share_tab == 2 {
        if state.camera_sources.is_empty() {
            l.label(
                "Nenhuma câmera enumerada. Confira a conexão e a permissão de câmera do sistema.",
                12.0,
                MUTED,
            )
            .into()
        } else {
            cameras.into()
        }
    } else {
        l.label("Fonte não reconhecida.", 12.0, MUTED).into()
    };
    let share_action = if state.screen_sharing_active {
        Some(Message::StopScreenShare)
    } else if state.call_rtc_session.is_some()
        && state.share_tab == 0
        && state.selected_source.is_some()
    {
        Some(Message::StartScreenShare)
    } else if state.call_rtc_session.is_some()
        && state.share_tab == 1
        && (state.selected_window.is_some() || crate::screen_capture::uses_wayland_window_portal())
    {
        Some(Message::StartWindowShare)
    } else if state.call_rtc_session.is_some()
        && state.share_tab == 2
        && state.selected_camera.is_some()
    {
        Some(Message::StartCameraShare)
    } else {
        None
    };
    let share_disabled = share_action.is_none();
    let share_label = if state.screen_sharing_active {
        "Parar compartilhamento"
    } else if state.share_tab == 2 {
        "Compartilhar câmera na chamada"
    } else if state.share_tab == 1 && crate::screen_capture::uses_wayland_window_portal() {
        "Escolher janela e compartilhar"
    } else if state.share_tab == 1 {
        "Compartilhar janela na chamada"
    } else {
        "Compartilhar tela na chamada"
    };
    let (refresh_label, refresh_message) = match state.share_tab {
        1 => ("Atualizar janelas", Message::RefreshWindows),
        2 => ("Atualizar câmeras", Message::RefreshCameras),
        _ => ("Atualizar telas", Message::RefreshScreens),
    };
    let (preview_icon, preview_label, preview_message, preview_disabled) = match state.share_tab {
        1 if crate::screen_capture::uses_wayland_window_portal() => (
            "window",
            "Escolher janela para prévia",
            Some(Message::CapturePortalWindowPreview),
            false,
        ),
        1 => (
            "window",
            "Capturar prévia local",
            state.selected_window.map(Message::CaptureWindow),
            state.selected_window.is_none(),
        ),
        2 => (
            "camera",
            "Capturar prévia local",
            state.selected_camera.clone().map(Message::CaptureCamera),
            state.selected_camera.is_none(),
        ),
        _ => (
            "screen",
            "Capturar prévia",
            state.selected_source.map(Message::CaptureScreen),
            state.selected_source.is_none(),
        ),
    };
    let body = column![
        l.title("O que você quer mostrar à roda?", 36.0),
        l.label(
            "H.264/SFRAME · transmissão disponível durante chamada ativa",
            12.0,
            MUTED
        ),
        tabs,
        row![
            column![
                l.label("FONTES DISPONÍVEIS", 11.0, GOLD),
                scrollable(source_list).height(l.px(290.0)).width(Fill),
                l.label(state.screen_capture_status.clone(), 11.0, MUTED),
                l.label(
                    state.screen_share_status.clone(),
                    11.0,
                    if state.screen_sharing_active {
                        GREEN
                    } else {
                        MUTED
                    }
                ),
                row![
                    l.control("refresh", refresh_label, Some(refresh_message), false),
                    l.control(
                        preview_icon,
                        preview_label,
                        preview_message,
                        preview_disabled
                    )
                ]
                .spacing(l.px(10.0))
            ]
            .spacing(l.px(12.0))
            .width(Fill),
            column![
                l.label(
                    if state.share_tab == 2 {
                        "PRÉVIA DA CÂMERA"
                    } else if state.share_tab == 1 {
                        "PRÉVIA DA JANELA"
                    } else {
                        "PRÉVIA DA TELA"
                    },
                    11.0,
                    GOLD
                ),
                preview
            ]
            .spacing(l.px(10.0))
            .width(Fill)
        ]
        .spacing(l.px(20.0)),
        row![
            l.control(
                "close",
                "Cancelar",
                Some(Message::Navigate(Screen::Call)),
                false
            ),
            space().width(Fill),
            l.control("screen", share_label, share_action, share_disabled)
        ]
        .spacing(l.px(20.0))
    ]
    .spacing(l.px(20.0));
    l.place(l.panel(body), 126.0, 94.0, 1028.0, 646.0)
}
fn mls(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let local_group_rows = state
        .mls_groups
        .iter()
        .map(|group| -> Element<'_, Message> {
            let group_id = crate::hex_encode_bytes(&group.group_id);
            row![
                column![
                    l.label(
                        format!("{}… · epoch {}", &group_id[..16], group.epoch),
                        10.0,
                        PAPER
                    ),
                    if group.quarantined {
                        l.label("EM QUARENTENA", 9.0, GOLD)
                    } else if !group.active {
                        l.label("REMOVIDO / INATIVO NESTE DISPOSITIVO", 9.0, RED)
                    } else {
                        l.label(
                            if group.purpose == peer::MlsGroupPurpose::Call {
                                "CHAMADA · local"
                            } else {
                                "CONVERSA · local"
                            },
                            9.0,
                            MUTED,
                        )
                    }
                ]
                .spacing(l.px(2.0)),
                space().width(Fill),
                button(l.label("Abrir", 10.0, PAPER))
                    .on_press(Message::SelectMlsGroup(group.group_id.to_vec()))
                    .padding([l.px(5.0), l.px(9.0)])
                    .style(|_, status| button_style(status, false, false))
            ]
            .align_y(iced::Center)
            .spacing(l.px(6.0))
            .into()
        })
        .collect::<Vec<_>>();
    let local_groups = if let Some(error) = state.mls_groups_error.as_deref() {
        let message = if error.contains("credential store") || error.contains("Secret Service") {
            "Secret Service indisponível; verifique o cofre e atualize."
        } else {
            "Não foi possível carregar os grupos locais."
        };
        vec![l.label(message, 10.0, RED).into()]
    } else if local_group_rows.is_empty() {
        vec![
            l.label("Nenhum grupo salvo neste dispositivo.", 10.0, MUTED)
                .into(),
        ]
    } else {
        local_group_rows
    };
    let selected_group_active = state
        .mls_groups
        .iter()
        .find(|group| Some(group.group_id.as_slice()) == state.mls_history_group.as_deref())
        .is_some_and(|group| group.active && !group.quarantined);
    let recipient_rows = state
        .mls_commit_recipients
        .iter()
        .take(3)
        .map(|recipient| -> Element<'_, Message> {
            let device = crate::hex_encode_bytes(&recipient.device_public_key);
            l.label(
                format!(
                    "epoch {} · {}… · {}",
                    recipient.epoch,
                    &device[..12],
                    if recipient.delivered {
                        "ACK persistido"
                    } else {
                        "aguardando ACK"
                    }
                ),
                10.0,
                if recipient.delivered { GREEN } else { MUTED },
            )
            .into()
        })
        .collect::<Vec<_>>();
    let recipient_rows = if recipient_rows.is_empty() {
        vec![
            l.label("Nenhum Commit distribuído neste grupo ainda.", 10.0, MUTED)
                .into(),
        ]
    } else {
        recipient_rows
    };
    let recipient_status = column![
        l.label("ENTREGA DE COMMITS · POR DISPOSITIVO", 10.0, GOLD),
        column(recipient_rows).spacing(l.px(3.0))
    ]
    .spacing(l.px(4.0));
    let local_device = match state.identity_status {
        crate::IdentityStatus::Ready(device) => Some(device),
        _ => None,
    };
    let can_remove_members = local_device.is_some_and(|device| {
        state
            .mls_groups
            .iter()
            .find(|group| Some(group.group_id.as_slice()) == state.mls_history_group.as_deref())
            .is_some_and(|group| group.designated_committer_device == device)
    }) && state.mls_quarantine_reason.is_none()
        && selected_group_active;
    let member_rows = state
        .mls_member_devices
        .iter()
        .map(|device| -> Element<'_, Message> {
            let encoded = crate::hex_encode_bytes(device);
            let is_local = local_device == Some(*device);
            let confirming = state.mls_remove_confirmation == Some(*device);
            let action: Element<'_, Message> = if confirming {
                row![
                    button(l.label("Confirmar", 9.0, NIGHT))
                        .on_press(Message::ConfirmMlsMemberRemoval)
                        .padding([l.px(3.0), l.px(6.0)])
                        .style(|_, status| button_style(status, true, false)),
                    button(l.label("Cancelar", 9.0, PAPER))
                        .on_press(Message::CancelMlsMemberRemoval)
                        .padding([l.px(3.0), l.px(6.0)])
                        .style(|_, status| button_style(status, false, false)),
                ]
                .spacing(l.px(3.0))
                .into()
            } else if can_remove_members && !is_local {
                button(l.label("Remover", 9.0, PAPER))
                    .on_press(Message::RequestMlsMemberRemoval(*device))
                    .padding([l.px(3.0), l.px(6.0)])
                    .style(|_, status| button_style(status, false, false))
                    .into()
            } else {
                space().width(l.px(100.0)).into()
            };
            row![
                button(l.label(
                    format!(
                        "{}…{}",
                        &encoded[..12],
                        if is_local { " · este dispositivo" } else { "" }
                    ),
                    9.0,
                    PAPER
                ))
                .on_press(Message::CopyMlsValue(encoded))
                .padding([l.px(2.0), l.px(4.0)])
                .style(|_, status| button_style(status, false, false)),
                space().width(Fill),
                action,
            ]
            .align_y(iced::Center)
            .spacing(l.px(4.0))
            .into()
        })
        .collect::<Vec<_>>();
    let member_rows = if member_rows.is_empty() {
        vec![
            l.label("Selecione um grupo para ver os dispositivos.", 9.0, MUTED)
                .into(),
        ]
    } else {
        member_rows
    };
    let member_note: Element<'_, Message> = if can_remove_members {
        l.label(
            "Remover cria um Commit MLS e revoga o acesso após os membros aplicarem a nova época.",
            8.0,
            MUTED,
        )
        .into()
    } else {
        space().height(l.px(0.0)).into()
    };
    let member_management = column![
        l.label("MEMBROS · CHAVES DE DISPOSITIVO", 9.0, GOLD),
        scrollable(column(member_rows).spacing(l.px(2.0))).height(l.px(66.0)),
        member_note,
    ]
    .spacing(l.px(3.0));
    let inviter = column![
        l.title("1 · Criar e convidar", 21.0),
        l.label("O criador do grupo é o committer designado.", 11.0, MUTED),
        l.control(
            "plus",
            "Criar grupo neste dispositivo",
            Some(Message::CreateMlsGroup),
            true
        ),
        l.label("ID DO GRUPO", 10.0, GOLD),
        l.input(
            "ID em hexadecimal",
            &state.mls_group_id,
            Message::MlsGroupIdChanged
        ),
        l.control(
            "key",
            "Copiar ID do grupo",
            (!state.mls_group_id.is_empty())
                .then(|| Message::CopyMlsValue(state.mls_group_id.clone())),
            false
        ),
        row![
            l.label("GRUPOS LOCAIS", 9.0, GOLD),
            button(l.label("↻", 11.0, PAPER))
                .on_press(Message::RefreshMlsGroups)
                .padding([l.px(4.0), l.px(7.0)])
                .style(|_, status| button_style(status, false, false))
        ]
        .align_y(iced::Center),
        column(local_groups).spacing(l.px(4.0)),
        member_management,
        rule(LINE, 1.0),
        l.label("PROPOSTA DE UPDATE RECEBIDA DO MEMBRO", 10.0, GOLD),
        l.input(
            "Cole a proposta hexadecimal",
            &state.mls_received_update_proposal,
            Message::MlsReceivedUpdateProposalChanged
        ),
        l.control(
            "check",
            "Autenticar e guardar proposta",
            Some(Message::ApplyMlsUpdateProposal),
            state.mls_quarantine_reason.is_none() && selected_group_active
        ),
        rule(LINE, 1.0),
        l.label("KEYPACKAGE RECEBIDO DO CONVIDADO", 10.0, GOLD),
        l.input(
            "Cole o KeyPackage público",
            &state.mls_invite_key_package,
            Message::MlsInviteKeyPackageChanged
        ),
        l.control(
            "users",
            "Validar e admitir membro",
            Some(Message::AdmitMlsMember),
            state.mls_quarantine_reason.is_none() && selected_group_active
        ),
        l.label("COMMIT PÚBLICO · DISTRIBUA AOS MEMBROS ATUAIS", 10.0, GOLD),
        l.input(
            "Commit hexadecimal",
            &state.mls_commit,
            Message::MlsCommitChanged
        ),
        l.control(
            "key",
            "Copiar Commit",
            (!state.mls_commit.is_empty()).then(|| Message::CopyMlsValue(state.mls_commit.clone())),
            false
        ),
        l.control(
            "arrow",
            "Enviar Commits pendentes ao membro conectado",
            Some(Message::DistributeMlsCommit),
            state.mls_quarantine_reason.is_none() && selected_group_active
        ),
        l.control(
            "users",
            if state.mls_fanout_running {
                "Distribuindo Commits…"
            } else {
                "Distribuir a todos os peers salvos"
            },
            Some(Message::DistributeMlsCommitsToAll),
            state.mls_quarantine_reason.is_none() && selected_group_active
                && !state.mls_fanout_running
                && !state.mls_event_fanout_running
                && state.peer_listener_handle.is_none()
        ),
        l.label(
            "Usa rotas pinadas salvas; encerre o listener/sessão atual. Cada próximo Commit aguarda o ACK durável do anterior.",
            10.0,
            MUTED
        ),
        l.control(
            "chat",
            if state.mls_event_fanout_running {
                "Distribuindo mensagens…"
            } else {
                "Distribuir mensagens MLS aos peers salvos"
            },
            Some(Message::DistributeMlsEventsToAll),
            state.mls_quarantine_reason.is_none() && selected_group_active
                && !state.mls_fanout_running
                && !state.mls_event_fanout_running
                && state.peer_listener_handle.is_none()
        ),
        l.label(
            "Envia mensagens pendentes pela rota de cada membro e espera o ACK. Entregue antes os Commits pendentes de cada peer.",
            10.0,
            MUTED
        ),
        l.label("WELCOME · COPIE PARA O DISPOSITIVO CONVIDADO", 10.0, GOLD),
        l.input(
            "Welcome hexadecimal",
            &state.mls_welcome,
            Message::MlsWelcomeChanged
        ),
        l.control(
            "key",
            "Copiar Welcome",
            (!state.mls_welcome.is_empty())
                .then(|| Message::CopyMlsValue(state.mls_welcome.clone())),
            false
        ),
        l.label("RATCHET TREE · COPIE PARA O CONVIDADO", 10.0, GOLD),
        l.input(
            "Ratchet tree hexadecimal",
            &state.mls_ratchet_tree,
            Message::MlsRatchetTreeChanged
        ),
        l.control(
            "key",
            "Copiar ratchet tree",
            (!state.mls_ratchet_tree.is_empty())
                .then(|| Message::CopyMlsValue(state.mls_ratchet_tree.clone())),
            false
        ),
        rule(LINE, 1.0),
        l.label("COMMIT RECEBIDO DO MEMBRO DESIGNADO", 10.0, GOLD),
        l.input(
            "Cole o Commit hexadecimal",
            &state.mls_received_commit,
            Message::MlsReceivedCommitChanged
        ),
        l.control(
            "check",
            "Autenticar e aplicar Commit",
            Some(Message::ApplyMlsCommit),
            state.mls_quarantine_reason.is_none() && selected_group_active
        )
    ]
    .spacing(l.px(9.0));
    let invitee = column![
        l.title("2 · Entrar em um grupo", 21.0),
        l.label(
            "Envie o KeyPackage ao committer; o Welcome volta por esta sessão.",
            11.0,
            MUTED
        ),
        l.control(
            "key",
            "Gerar meu KeyPackage",
            Some(Message::PrepareMlsKeyPackage),
            true
        ),
        l.input(
            "KeyPackage público hexadecimal",
            &state.mls_key_package,
            Message::MlsKeyPackageChanged
        ),
        l.control(
            "key",
            "Copiar KeyPackage para convidar",
            (!state.mls_key_package.is_empty())
                .then(|| Message::CopyMlsValue(state.mls_key_package.clone())),
            false
        ),
        l.control(
            "arrow",
            "Enviar KeyPackage ao committer conectado",
            (!state.mls_key_package.is_empty()).then_some(Message::SendMlsKeyPackage),
            matches!(state.peer_listen_status, crate::PeerListenStatus::Connected)
                && state.mls_quarantine_reason.is_none()
        ),
        l.label("ATUALIZAÇÃO DA MINHA CHAVE MLS", 10.0, GOLD),
        l.control(
            "key",
            "Criar proposta para atualizar minha chave",
            Some(Message::CreateMlsUpdateProposal),
            state.mls_quarantine_reason.is_none() && selected_group_active
        ),
        l.input(
            "Proposta assinada hexadecimal",
            &state.mls_update_proposal,
            Message::MlsUpdateProposalChanged
        ),
        l.control(
            "arrow",
            "Enviar proposta ao committer conectado",
            (!state.mls_update_proposal.is_empty()).then_some(Message::SendMlsUpdateProposal),
            state.mls_quarantine_reason.is_none() && selected_group_active
        ),
        l.control(
            "key",
            "Copiar proposta para o committer",
            (!state.mls_update_proposal.is_empty())
                .then(|| Message::CopyMlsValue(state.mls_update_proposal.clone())),
            false
        ),
        rule(LINE, 1.0),
        l.label("COLE O WELCOME RECEBIDO", 10.0, GOLD),
        l.input(
            "Welcome hexadecimal",
            &state.mls_welcome,
            Message::MlsWelcomeChanged
        ),
        l.label("COLE O RATCHET TREE RECEBIDO", 10.0, GOLD),
        l.input(
            "Ratchet tree hexadecimal",
            &state.mls_ratchet_tree,
            Message::MlsRatchetTreeChanged
        ),
        l.control(
            "users",
            "Validar Welcome e entrar",
            Some(Message::JoinMlsGroup),
            true
        ),
        l.label("ID DO GRUPO APÓS ENTRAR", 10.0, GOLD),
        l.input(
            "ID em hexadecimal",
            &state.mls_group_id,
            Message::MlsGroupIdChanged
        ),
        l.control(
            "key",
            "Copiar ID do grupo",
            (!state.mls_group_id.is_empty())
                .then(|| Message::CopyMlsValue(state.mls_group_id.clone())),
            false
        )
    ]
    .spacing(l.px(9.0));
    let history = scrollable(
        column(
            state
                .mls_history
                .iter()
                .map(|message| {
                    let outgoing = message.direction == storage::DirectMessageDirection::Sent;
                    let content: Element<'_, Message> =
                        match FileAttachmentOffer::decode_mls_text(&message.text) {
                            Ok(Some(attachment)) => {
                                let transfer_id = attachment.offer.transfer_id;
                                let filename = attachment.offer.filename.clone();
                                let details =
                                    format!("{} · {}", filename, attachment.offer.total_bytes);
                                let save = button(l.label("Salvar arquivo", 11.0, NIGHT))
                                    .on_press(Message::SaveMlsAttachment(
                                        transfer_id,
                                        filename.clone(),
                                    ))
                                    .padding([l.px(6.0), l.px(10.0)])
                                    .style(|_, status| button_style(status, true, false));
                                column![
                                    l.label("ANEXO CIFRADO", 10.0, GOLD),
                                    l.label(details, 12.0, PAPER),
                                    save,
                                    l.label(
                                        if outgoing {
                                            "Enviado · MLS"
                                        } else {
                                            "Recebido · MLS"
                                        },
                                        10.0,
                                        MUTED
                                    )
                                ]
                                .spacing(l.px(5.0))
                                .into()
                            }
                            _ => column![
                                l.label(message.text.clone(), 13.0, PAPER),
                                l.label(
                                    if outgoing {
                                        "Enviada · sessão atual"
                                    } else {
                                        "Recebida · sessão atual"
                                    },
                                    10.0,
                                    MUTED
                                )
                            ]
                            .spacing(l.px(4.0))
                            .into(),
                        };
                    container(content)
                        .padding(l.px(10.0))
                        .width(Length::Shrink)
                        .style(move |_| container::Style {
                            background: Some((if outgoing { NIGHT } else { PANEL }).into()),
                            border: Border {
                                color: LINE,
                                width: 1.0,
                                radius: 0.0.into(),
                            },
                            ..Default::default()
                        })
                        .into()
                })
                .collect::<Vec<Element<'_, Message>>>(),
        )
        .spacing(l.px(8.0)),
    );
    let can_send = matches!(state.peer_listen_status, crate::PeerListenStatus::Connected)
        && !state.mls_message_draft.trim().is_empty()
        && state.mls_history_group.is_some()
        && state.mls_quarantine_reason.is_none()
        && selected_group_active;
    let send = button(l.label("Enviar MLS", 14.0, NIGHT))
        .on_press_maybe(can_send.then_some(Message::SendMlsApplication))
        .padding([l.px(13.0), l.px(20.0)])
        .style(|_, status| button_style(status, true, false));
    let can_attach = matches!(state.peer_listen_status, crate::PeerListenStatus::Connected)
        && state.mls_history_group.is_some()
        && state.mls_quarantine_reason.is_none()
        && selected_group_active;
    let attach = button(l.label("Anexar arquivo", 12.0, PAPER))
        .on_press_maybe(can_attach.then_some(Message::PickMlsAttachment))
        .padding([l.px(10.0), l.px(14.0)])
        .style(|_, status| button_style(status, false, false));
    let retry = button(l.label("Reenviar pendentes", 12.0, PAPER))
        .on_press_maybe(
            (matches!(state.peer_listen_status, crate::PeerListenStatus::Connected)
                && state.mls_history_group.is_some()
                && state.mls_quarantine_reason.is_none()
                && selected_group_active)
                .then_some(Message::RetryQueuedMlsEvents),
        )
        .padding([l.px(12.0), l.px(16.0)])
        .style(|_, status| button_style(status, false, false));
    let retry_attachment = button(l.label(
        format!("Reenviar anexo ({})", state.mls_attachment_transfers.len()),
        12.0,
        PAPER,
    ))
    .on_press_maybe(
        (!state.mls_attachment_transfers.is_empty()
            && matches!(state.peer_listen_status, crate::PeerListenStatus::Connected)
            && selected_group_active)
            .then_some(Message::RetryMlsAttachmentBlob),
    )
    .padding([l.px(12.0), l.px(16.0)])
    .style(|_, status| button_style(status, false, false));
    let quarantine_banner: Element<'_, Message> =
        if let Some(reason) = state.mls_quarantine_reason.as_ref() {
            container(
                column![
                    l.label("ALERTA DE SEGURANÇA · GRUPO EM QUARENTENA", 11.0, GOLD),
                    l.label(reason.clone(), 11.0, PAPER),
                    l.label(
                        "Envio, retry e novos Commits estão bloqueados neste dispositivo.",
                        10.0,
                        PAPER
                    ),
                ]
                .spacing(l.px(4.0)),
            )
            .padding(l.px(10.0))
            .width(Fill)
            .style(|_| container::Style {
                background: Some(RED.into()),
                border: Border {
                    color: GOLD,
                    width: 1.0,
                    radius: 0.0.into(),
                },
                ..Default::default()
            })
            .into()
        } else {
            space().height(l.px(0.0)).into()
        };
    let proposal_review = column(
        std::iter::once(
            l.label(
                format!(
                    "REVISÃO DE PROPOSTAS · {} pendente(s) · {} aprovada(s) · {} rejeitada(s)",
                    state
                        .mls_pending_proposals
                        .iter()
                        .filter(|proposal| !proposal.approved && !proposal.rejected)
                        .count(),
                    state
                        .mls_pending_proposals
                        .iter()
                        .filter(|proposal| proposal.approved)
                        .count(),
                    state
                        .mls_pending_proposals
                        .iter()
                        .filter(|proposal| proposal.rejected)
                        .count()
                ),
                10.0,
                GOLD,
            )
            .into(),
        )
        .chain(state.mls_pending_proposals.iter().take(3).map(|proposal| {
            let author = crate::hex_encode_bytes(&proposal.author_device);
            let id = crate::hex_encode_bytes(&proposal.proposal_id);
            let review_actions: Element<'_, Message> = if proposal.approved || proposal.rejected {
                space().width(l.px(180.0)).into()
            } else {
                row![
                        button(
                            row![l.icon("check", PAPER, 11.0), l.label("Aprovar", 9.0, PAPER)]
                                .spacing(l.px(4.0))
                                .align_y(iced::Center)
                        )
                        .on_press_maybe(
                            (state.mls_quarantine_reason.is_none() && selected_group_active)
                                .then_some(Message::SetMlsProposalApproval(
                                    proposal.proposal_id,
                                    true
                                ),)
                        )
                        .padding([l.px(4.0), l.px(7.0)])
                        .style(|_, status| button_style(status, false, false)),
                        button(
                            row![
                                l.icon("close", PAPER, 11.0),
                                l.label("Rejeitar", 9.0, PAPER)
                            ]
                            .spacing(l.px(4.0))
                            .align_y(iced::Center)
                        )
                        .on_press_maybe(
                            (state.mls_quarantine_reason.is_none() && selected_group_active)
                                .then_some(Message::SetMlsProposalApproval(
                                    proposal.proposal_id,
                                    false
                                ),)
                        )
                        .padding([l.px(4.0), l.px(7.0)])
                        .style(|_, status| button_style(status, false, false)),
                    ]
                .spacing(l.px(5.0))
                .into()
            };
            row![
                l.label(
                    format!(
                        "Update · membro {}… · proposta {}… · {}",
                        &author[..12],
                        &id[..12],
                        if proposal.approved {
                            "aprovada"
                        } else if proposal.rejected {
                            "rejeitada"
                        } else {
                            "pendente"
                        }
                    ),
                    9.0,
                    PAPER,
                ),
                review_actions,
            ]
            .spacing(l.px(5.0))
            .into()
        }))
        .chain(std::iter::once(
            l.control(
                "users",
                "Criar Commit com propostas aprovadas",
                Some(Message::CommitMlsProposals),
                state.mls_quarantine_reason.is_none()
                    && selected_group_active
                    && state
                        .mls_pending_proposals
                        .iter()
                        .any(|proposal| proposal.approved),
            ),
        ))
        .collect::<Vec<Element<'_, Message>>>(),
    )
    .spacing(l.px(3.0));
    let body = column![
        row![
            column![l.title("Grupo MLS", 28.0), l.label("OpenMLS · SQLCipher · Iroh/QUIC direto", 11.0, MUTED)].spacing(l.px(5.0)),
            space().width(Fill),
            l.label("CONVITE DIRETO · CHAVES PRIVADAS LOCAIS", 10.0, GOLD)
        ].align_y(iced::Center),
        rule(LINE, 1.0),
        quarantine_banner,
        row![
            scrollable(inviter).height(l.px(275.0)).width(Fill),
            rule(LINE, 1.0),
            scrollable(invitee).height(l.px(275.0)).width(Fill)
        ].spacing(l.px(18.0)),
        l.label(state.mls_status.clone(), 11.0, GREEN),
        recipient_status,
        proposal_review,
        l.label("TRANSCRIÇÃO MLS · ARMAZENADA LOCALMENTE", 10.0, GOLD),
        container(history).height(l.px(78.0)).width(Fill),
        row![
            container(l.input("Mensagem MLS · até 16 KiB", &state.mls_message_draft, Message::MlsMessageDraftChanged)).width(Fill),
            attach,
            send,
            retry,
            retry_attachment
        ].spacing(l.px(10.0)),
        l.label(
            "Convites e árvores ainda são trocados manualmente por canal confiável. Mensagens MLS seguem pela sessão autenticada ativa e só recebem ACK depois da validação e persistência no outro dispositivo.",
            10.0,
            MUTED
        )
    ]
    .spacing(l.px(12.0));
    l.place(l.panel(body), 24.0, 80.0, 1232.0, 676.0)
}

fn chat(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let identity_ready = matches!(state.identity_status, crate::IdentityStatus::Ready(_));
    let listener_active = matches!(
        state.peer_listen_status,
        crate::PeerListenStatus::Starting { .. }
            | crate::PeerListenStatus::Listening { .. }
            | crate::PeerListenStatus::Connected
            | crate::PeerListenStatus::Unauthorized(_)
    );
    let session_connected = matches!(state.peer_listen_status, crate::PeerListenStatus::Connected);
    let (identity_detail, copy_message, copy_label) = match &state.identity_status {
        crate::IdentityStatus::Ready(public_key) => (
            public_key
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            Some(Message::CopyDeviceKey),
            if state.identity_key_copied {
                "Chave copiada"
            } else {
                "Copiar minha chave pública"
            },
        ),
        crate::IdentityStatus::Missing => (
            "Crie uma identidade para usar o transporte direto.".to_owned(),
            Some(Message::CreateIdentity),
            "Criar identidade do dispositivo",
        ),
        crate::IdentityStatus::Loading => (
            "Carregando chave do cofre do sistema…".to_owned(),
            None,
            "Identidade carregando",
        ),
        crate::IdentityStatus::Creating => (
            "Criando chave no cofre do sistema…".to_owned(),
            None,
            "Criando identidade",
        ),
        crate::IdentityStatus::Failed => (
            "Cofre do sistema indisponível. Confira o Secret Service.".to_owned(),
            Some(Message::CreateIdentity),
            "Tentar carregar identidade",
        ),
    };
    let identity = column![
        l.label("SUA IDENTIDADE DO DISPOSITIVO", 10.0, GOLD),
        l.label(identity_detail, 10.0, PAPER),
        l.control("key", copy_label, copy_message, !identity_ready),
        rule(LINE, 1.0),
        l.label("CHAVE PÚBLICA DO PEER · PIN MANUAL", 10.0, GOLD),
        l.input_maybe(
            "64 caracteres hexadecimais",
            &state.peer_public_key,
            (!listener_active).then_some(Message::PeerPublicKeyChanged as fn(String) -> Message)
        ),
        l.label(
            if listener_active {
                "Aguardando: esta deve ser a chave de quem vai conectar. Compartilhe sua chave e um endereço anunciado abaixo."
            } else {
                "Para conectar, cole a chave de quem está aguardando. Para receber, cada lado aguarda e fixa a chave do outro."
            },
            10.0,
            MUTED
        ),
        l.label(
            if state.peer_public_key.is_empty() {
                "NENHUMA CHAVE DE PEER SELECIONADA"
            } else if state.peer_key_verified {
                "IDENTIDADE VERIFICADA LOCALMENTE"
            } else {
                "IDENTIDADE AINDA NÃO VERIFICADA"
            },
            9.0,
            if state.peer_key_verified { GREEN } else { GOLD }
        ),
        l.control(
            "shield",
            "Conferir identidade do peer",
            Some(Message::Navigate(Screen::Verify)),
            false
        ),
        l.label("RELAY DO GRUPO · OPCIONAL", 10.0, GOLD),
        l.label(
            "Relay próprio em HTTPS; o mesmo URL/token precisa estar configurado em cada membro.",
            10.0,
            MUTED
        ),
        l.input_maybe(
            "https://relay.example.org",
            &state.peer_relay_url,
            (!listener_active).then_some(Message::PeerRelayUrlChanged as fn(String) -> Message)
        ),
        l.secret_input(
            "Token compartilhado do relay",
            &state.peer_relay_token,
            Message::PeerRelayTokenChanged
        ),
        row![
            l.control(
                "check",
                "Salvar relay",
                (state.peer_relay_config_dirty && !listener_active)
                    .then_some(Message::SavePeerRelayConfig),
                false
            ),
            l.control(
                "close",
                "Descartar",
                state
                    .peer_relay_config_dirty
                    .then_some(Message::DiscardPeerRelayConfig),
                false
            )
        ]
        .spacing(l.px(6.0)),
        l.label(state.peer_relay_config_status.clone(), 10.0, MUTED),
        l.label("PORTA UDP PARA RECEBER", 10.0, GOLD),
        l.input_maybe(
            "45873",
            &state.peer_listen_port,
            (!listener_active).then_some(Message::PeerListenPortChanged as fn(String) -> Message)
        )
    ]
    .spacing(l.px(10.0));
    let listener_status: Element<'_, Message> = match &state.peer_listen_status {
        crate::PeerListenStatus::Idle => l
            .label(
                "Listener parado. Ao iniciar, aceita uma sessão persistente do peer pinado.",
                11.0,
                MUTED,
            )
            .into(),
        crate::PeerListenStatus::Starting { port } => l
            .label(format!("Abrindo listener UDP na porta {port}…"), 11.0, GOLD)
            .into(),
        crate::PeerListenStatus::Listening { port, addresses } => {
            let direct = addresses
                .iter()
                .filter(|address| !address.ip().is_unspecified() && !address.ip().is_loopback())
                .collect::<Vec<_>>();
            if direct.is_empty() {
                l.label(
                    format!(
                        "Aguardando sessão · UDP {port}. Nenhum endereço de rede foi anunciado; consulte as interfaces de rede. Não compartilhe 0.0.0.0: é um endereço curinga."
                    ),
                    11.0,
                    GREEN,
                )
                .into()
            } else {
                let addresses = direct
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("  ou  ");
                let mut copy_buttons = column![];
                for address in &direct {
                    copy_buttons = copy_buttons.push(
                        column![
                            l.label(address.to_string(), 11.0, GREEN),
                            l.control(
                                "key",
                                "Copiar este endereço",
                                Some(Message::CopyPeerListenAddress(address.to_string())),
                                false,
                            )
                        ]
                        .spacing(l.px(4.0)),
                    );
                }
                column![
                    l.label(
                        format!(
                            "Aguardando sessão · escolha um endereço para compartilhar: {addresses}"
                        ),
                        11.0,
                        GREEN
                    ),
                    copy_buttons.spacing(l.px(8.0))
                ]
                .spacing(l.px(6.0))
                .into()
            }
        }
        crate::PeerListenStatus::Connected => l
            .label("Conectado · sessão autenticada ativa", 11.0, GREEN)
            .into(),
        crate::PeerListenStatus::Disconnected(reason) => l
            .label(format!("Desconectado: {reason}"), 11.0, MUTED)
            .into(),
        crate::PeerListenStatus::Unauthorized(reason) => l
            .label(
                format!("Peer recusado: {reason}"),
                11.0,
                Color::from_rgb8(255, 145, 159),
            )
            .into(),
        crate::PeerListenStatus::Failed(error) => l
            .label(
                format!("Listener: {error}"),
                11.0,
                Color::from_rgb8(255, 145, 159),
            )
            .into(),
    };
    let listen_button = match state.peer_listen_status {
        crate::PeerListenStatus::Starting { .. }
        | crate::PeerListenStatus::Listening { .. }
        | crate::PeerListenStatus::Unauthorized(_)
        | crate::PeerListenStatus::Connected => l.control(
            "close",
            if session_connected {
                "Desconectar sessão"
            } else {
                "Parar listener"
            },
            Some(Message::StopPeerListener),
            false,
        ),
        _ => l.control(
            "headphones",
            if identity_ready {
                "Aguardar peer"
            } else {
                "Identidade necessária para escutar"
            },
            identity_ready.then_some(Message::StartPeerListener),
            true,
        ),
    };
    let listening = column![
        listen_button,
        listener_status,
        l.label(
            "Sem relay: libere UDP na rede. Com relay: URL e token precisam corresponder ao servidor do grupo.",
            10.0,
            MUTED
        )
    ]
    .spacing(l.px(9.0));
    let local = l.panel(column![identity, rule(LINE, 1.0), listening].spacing(l.px(13.0)));

    let send_action = if identity_ready
        && !listener_active
        && !matches!(state.peer_send_status, crate::PeerSendStatus::Connecting)
    {
        Some(Message::SendPeerText)
    } else {
        session_connected.then_some(Message::SendPeerText)
    };
    let send_address = row![
        column![
            l.label("ENDEREÇO DO LISTENER · LAN OU VPN", 10.0, GOLD),
            l.input(
                "IP:porta de quem está aguardando",
                &state.peer_address,
                Message::PeerAddressChanged
            )
        ]
        .spacing(l.px(6.0))
        .width(Fill),
        column![
            l.label("MENSAGEM", 10.0, GOLD),
            l.input(
                "Texto simples · até 16 KiB",
                &state.peer_draft,
                Message::PeerDraftChanged
            )
        ]
        .spacing(l.px(6.0))
        .width(Fill),
        l.control(
            "arrow",
            if session_connected {
                "Enviar"
            } else {
                "Conectar e enviar"
            },
            send_action,
            true
        )
    ]
    .spacing(l.px(10.0))
    .align_y(iced::Bottom);
    let address_hint = l.label(
        "Use o IP e a porta mostrados no dispositivo que clicou em Aguardar peer. Em VPN, escolha o IP da interface VPN e libere essa porta UDP no firewall do listener. Endereço vazio usa o relay salvo.",
        10.0,
        MUTED,
    );
    let send_status: Element<'_, Message> = match &state.peer_send_status {
        crate::PeerSendStatus::Idle => l
            .label(
                if session_connected {
                    "Sessão ativa · envie várias mensagens pela mesma conexão."
                } else {
                    "Envio direto · use o IP anunciado que seja alcançável nesta rede ou VPN."
                },
                11.0,
                MUTED,
            )
            .into(),
        crate::PeerSendStatus::Connecting => {
            l.label("Conectando ao peer pinado…", 11.0, GOLD).into()
        }
        crate::PeerSendStatus::AwaitingAck => l.label("Aguardando ACK do peer…", 11.0, GOLD).into(),
        crate::PeerSendStatus::Sent => l
            .label(
                "ACK recebido e histórico salvo localmente; isso não confirma leitura.",
                11.0,
                GREEN,
            )
            .into(),
        crate::PeerSendStatus::Failed(error) => l
            .label(
                format!("Envio falhou: {error}"),
                11.0,
                Color::from_rgb8(255, 145, 159),
            )
            .into(),
    };
    let routes: Element<'_, Message> = if state.peer_routes_error.is_some() {
        l.label("ROTAS PINADAS: cofre local indisponível.", 10.0, GOLD)
            .into()
    } else if state.peer_routes.is_empty() {
        l.label(
            "ROTAS PINADAS: conecte a um peer para guardar a chave e o endereço usados.",
            10.0,
            MUTED,
        )
        .into()
    } else {
        let entries = state.peer_routes.iter().fold(
            column![l.label(
                format!("ROTAS PINADAS · {}", state.peer_routes.len()),
                10.0,
                GOLD
            )]
            .spacing(l.px(3.0)),
            |entries, route| {
                entries.push(l.label(
                    format!(
                        "{}… · {}",
                        crate::hex_encode_bytes(&route.device_public_key[..4]),
                        if route.relay_only {
                            "relay do grupo"
                        } else {
                            &route.address
                        }
                    ),
                    10.0,
                    MUTED,
                ))
            },
        );
        scrollable(entries).height(l.px(72.0)).into()
    };
    let transcript: Element<'_, Message> = if state.peer_transcript.is_empty() {
        container(
            l.label(
                "Sem mensagens para este peer. O histórico mostra apenas mensagens recebidas ou confirmadas e salvas neste dispositivo.",
                12.0,
                MUTED,
            )
            .align_x(iced::Alignment::Center),
        )
        .width(Fill)
        .height(Fill)
        .center(Fill)
        .into()
    } else {
        let entries =
            state
                .peer_transcript
                .iter()
                .fold(column![].spacing(l.px(12.0)), |entries, entry| {
                    let (label, outgoing) = match (entry.direction, entry.persisted) {
                        (crate::PeerMessageDirection::Sent, true) => {
                            ("Enviada · histórico local", true)
                        }
                        (crate::PeerMessageDirection::Received, true) => {
                            ("Recebida · histórico local", false)
                        }
                        (crate::PeerMessageDirection::Sent, false) => {
                            ("Enviada · sessão atual", true)
                        }
                        (crate::PeerMessageDirection::Received, false) => {
                            ("Recebida · sessão atual", false)
                        }
                    };
                    entries.push(bubble(l, &entry.text, label, outgoing))
                });
        scrollable(entries).height(Fill).into()
    };
    let can_clear_history = state.peer_history_loaded_for.as_deref()
        == Some(state.peer_public_key.as_str())
        && !listener_active
        && state.peer_pending_sends.is_empty()
        && !state.peer_history_clearing;
    let history_action: Element<'_, Message> = if state.peer_history_clear_confirmation {
        column![
            l.label(
                "Apagar permanentemente o histórico local deste peer?",
                11.0,
                GOLD
            ),
            row![
                l.control(
                    "close",
                    "Cancelar",
                    Some(Message::CancelClearPeerHistory),
                    false
                ),
                l.control(
                    "check",
                    "Apagar histórico",
                    Some(Message::ConfirmClearPeerHistory),
                    true
                )
            ]
            .spacing(l.px(10.0))
        ]
        .spacing(l.px(8.0))
        .into()
    } else if state.peer_history_clearing {
        l.label("Apagando histórico local…", 11.0, GOLD).into()
    } else if can_clear_history {
        l.control(
            "close",
            "Apagar histórico local deste peer",
            Some(Message::RequestClearPeerHistory),
            false,
        )
    } else if state.peer_history_loaded_for.as_deref() == Some(state.peer_public_key.as_str())
        && (listener_active || !state.peer_pending_sends.is_empty())
    {
        l.label(
            "Desconecte a sessão e aguarde as mensagens pendentes antes de apagar o histórico.",
            11.0,
            MUTED,
        )
        .into()
    } else {
        l.label(
            "Cole a chave pública do peer para carregar o histórico local.",
            11.0,
            MUTED,
        )
        .into()
    };
    let body = column![
        row![
            column![
                l.title("Texto direto", 28.0),
                l.label("Iroh/QUIC · LAN ou VPN · sem MLS", 11.0, MUTED)
            ]
            .spacing(l.px(5.0)),
            space().width(Fill),
            l.label("HISTÓRICO LOCAL CIFRADO POR PEER", 10.0, GOLD)
        ]
        .align_y(iced::Center),
        rule(LINE, 1.0),
        send_address,
        address_hint,
        send_status,
        routes,
        rule(LINE, 1.0),
        history_action,
        transcript,
        l.label(
            "QUIC cifra a sessão com a identidade pinada. O histórico fica no SQLCipher local deste dispositivo; ACK confirma recebimento antes do salvamento local do remetente, não leitura. Sem MLS, relay ou NAT traversal.",
            10.0,
            MUTED
        )
    ]
    .spacing(l.px(14.0));
    stack![
        l.place(local, 24.0, 80.0, 370.0, 676.0),
        l.place(l.panel(body), 408.0, 80.0, 848.0, 676.0)
    ]
    .width(Fill)
    .height(Fill)
    .into()
}
fn bubble(l: Layout, value: &str, time: &str, outgoing: bool) -> Element<'static, Message> {
    let c = container(
        column![l.label(value, 13.0, PAPER), l.label(time, 10.0, MUTED)].spacing(l.px(8.0)),
    )
    .padding(l.px(16.0))
    .max_width(l.px(560.0))
    .style(move |_| container::Style {
        background: Some(
            if outgoing {
                Color::from_rgb8(35, 28, 77)
            } else {
                PANEL
            }
            .into(),
        ),
        border: Border {
            color: LINE,
            width: 1.0,
            ..Default::default()
        },
        ..Default::default()
    });
    if outgoing {
        container(c).align_right(Fill).into()
    } else {
        container(c).align_left(Fill).into()
    }
}
fn incoming(state: &Slouching, l: Layout) -> Element<'_, Message> {
    if let Some(pending) = state.pending_call_offer.as_ref() {
        let peer_key = crate::hex_encode_key(&pending.peer_device);
        let can_accept =
            state.audio_input_selected.is_some() && state.audio_output_selected.is_some();
        let mut actions = row![
            l.control(
                "close",
                "Recusar chamada",
                Some(Message::RejectIncomingCall),
                true
            ),
            l.control(
                "phone",
                "Aceitar chamada de voz",
                Some(Message::AcceptIncomingCall),
                can_accept
            )
        ]
        .spacing(l.px(12.0));
        if !can_accept {
            actions = actions.push(l.control(
                "settings",
                "Configurar áudio",
                Some(Message::Navigate(Screen::Settings)),
                true,
            ));
        }
        return stack![
            l.place(
                container(l.title("Chamada de voz recebida", 42.0)).center_x(Fill),
                170.0,
                260.0,
                950.0,
                70.0
            ),
            l.place(
                container(l.label(
                    format!("Peer fixado · {}…", &peer_key[..peer_key.len().min(20)]),
                    15.0,
                    PAPER
                ))
                .center_x(Fill),
                180.0,
                350.0,
                930.0,
                42.0
            ),
            l.place(
                container(l.label(
                    if can_accept {
                        "Seu microfone só será aberto depois de aceitar e conectar."
                    } else {
                        "Selecione microfone e saída em Configurações antes de aceitar."
                    },
                    12.0,
                    VIOLET
                ))
                .center_x(Fill),
                180.0,
                402.0,
                930.0,
                36.0
            ),
            l.place(actions, 220.0, 475.0, 850.0, 62.0)
        ]
        .width(Fill)
        .height(Fill)
        .into();
    }

    let portrait = container(
        image(assets().images["frog"].clone())
            .width(l.px(154.0))
            .height(l.px(154.0))
            .content_fit(ContentFit::Cover)
            .border_radius(l.px(80.0)),
    )
    .padding(l.px(3.0))
    .style(|_| container::Style {
        border: Border {
            color: GOLD,
            width: 2.0,
            radius: 80.0.into(),
        },
        ..Default::default()
    });
    let actions = row![
        l.control(
            "close",
            "Recusar",
            Some(Message::Navigate(Screen::Home)),
            false
        ),
        l.control(
            "phone",
            "Prévia de voz",
            Some(Message::Navigate(Screen::Lobby)),
            false
        ),
        l.control(
            "camera",
            "Prévia de vídeo",
            Some(Message::Navigate(Screen::Lobby)),
            true
        )
    ]
    .spacing(l.px(16.0));
    let notification = column![
        l.label("NOTIFICAÇÃO · EXEMPLO", 10.0, MUTED),
        row![
            l.picture("gnome", 42.0, 42.0),
            column![
                l.label("Pim chama a roda", 14.0, PAPER),
                l.label("Nenhuma chamada recebida", 10.0, MUTED)
            ]
            .spacing(l.px(6.0))
        ]
        .spacing(l.px(12.0)),
        row![
            l.control(
                "close",
                "Agora não",
                Some(Message::Navigate(Screen::Home)),
                false
            ),
            l.control(
                "headphones",
                "Ver lobby",
                Some(Message::Navigate(Screen::Lobby)),
                true
            )
        ]
        .spacing(l.px(8.0))
    ]
    .spacing(l.px(14.0));
    stack![
        l.place(
            container(portrait).center_x(Fill),
            480.0,
            140.0,
            320.0,
            185.0
        ),
        l.place(
            container(l.label("C H A M A D A  D E  V Í D E O", 11.0, MUTED)).center_x(Fill),
            300.0,
            367.0,
            680.0,
            25.0
        ),
        l.place(
            container(l.title("Mara está batendo", 52.0)).center_x(Fill),
            210.0,
            408.0,
            860.0,
            80.0
        ),
        l.place(
            container(l.label(
                "Personagem da prévia · nenhuma chamada recebida",
                12.0,
                VIOLET
            ))
            .center_x(Fill),
            240.0,
            495.0,
            800.0,
            40.0
        ),
        l.place(actions, 310.0, 558.0, 660.0, 60.0),
        l.place(
            container(l.label("já vou, tô esquentando o caldeirão", 12.0, MUTED)).center_x(Fill),
            260.0,
            631.0,
            760.0,
            30.0
        ),
        l.place(l.panel(notification), 890.0, 606.0, 360.0, 182.0)
    ]
    .width(Fill)
    .height(Fill)
    .into()
}

fn verification(state: &Slouching, l: Layout) -> Element<'_, Message> {
    let listener_active = matches!(
        state.peer_listen_status,
        crate::PeerListenStatus::Starting { .. }
            | crate::PeerListenStatus::Listening { .. }
            | crate::PeerListenStatus::Connected
            | crate::PeerListenStatus::Unauthorized(_)
    );
    let own_key = match &state.identity_status {
        crate::IdentityStatus::Ready(key) => crate::hex_encode_bytes(key),
        crate::IdentityStatus::Missing => "Identidade ainda não criada".to_owned(),
        crate::IdentityStatus::Loading => "Carregando identidade do cofre…".to_owned(),
        crate::IdentityStatus::Creating => "Criando identidade…".to_owned(),
        crate::IdentityStatus::Failed => "Secret Service indisponível".to_owned(),
    };
    let peer_id = crate::parse_peer_id(&state.peer_public_key).ok();
    let current_peer_key = peer_id.map(|peer| crate::hex_encode_bytes(peer.as_bytes()));
    let peer_is_local = matches!(
        (&state.identity_status, peer_id),
        (crate::IdentityStatus::Ready(local), Some(peer)) if peer.as_bytes() == local
    );
    let can_toggle = current_peer_key.as_deref().is_some_and(|key| {
        state.peer_verification_loaded_for.as_deref() == Some(key)
            && matches!(state.identity_status, crate::IdentityStatus::Ready(_))
            && !peer_is_local
            && !listener_active
    });
    let own =
        l.panel(
            column![
            l.label("SUA CHAVE PÚBLICA DO DISPOSITIVO", 10.0, GOLD),
            l.label(own_key, 11.0, PAPER),
            l.control("key", "Copiar minha chave", Some(Message::CopyDeviceKey), false),
            l.control(
                "key",
                "Mostrar convite QR (10 min)",
                matches!(state.identity_status, crate::IdentityStatus::Ready(_))
                    .then_some(Message::OpenPeerInviteQr),
                false
            ),
            l.label(
                "Esta chave identifica este dispositivo; nome e familiar são apenas perfil local.",
                10.0,
                MUTED
            )
        ]
            .spacing(l.px(12.0)),
        );
    let mut address_choices = column![].spacing(l.px(4.0));
    for address in &state.peer_invite_addresses {
        let selected = state.peer_address == *address;
        address_choices = address_choices.push(
            button(l.label(
                format!("{} {address}", if selected { "✓" } else { "Usar" }),
                10.0,
                if selected { GOLD } else { PAPER },
            ))
            .on_press(Message::SelectPeerInviteAddress(address.clone()))
            .padding([l.px(5.0), l.px(8.0)])
            .width(Fill)
            .style(|_, status| button_style(status, false, false)),
        );
    }
    let invite_addresses: Element<'_, Message> = if state.peer_invite_addresses.is_empty() {
        l.label("Nenhum endereço importado do QR.", 10.0, MUTED)
            .into()
    } else {
        column![
            l.label("ENDEREÇOS DO CONVITE · ESCOLHA UM", 9.0, GOLD),
            scrollable(address_choices).height(l.px(100.0))
        ]
        .spacing(l.px(4.0))
        .into()
    };
    let peer = l.panel(
        column![
            l.label("CHAVE PÚBLICA DO PEER", 10.0, GOLD),
            l.input_maybe(
                "Cole os 64 caracteres hexadecimais",
                &state.peer_public_key,
                (!listener_active)
                    .then_some(Message::PeerPublicKeyChanged as fn(String) -> Message)
            ),
            row![
                l.control(
                    "key",
                    "Importar QR de PNG",
                    (!listener_active).then_some(Message::ImportPeerInviteQr),
                    false
                ),
                l.control(
                    if state.peer_invite_camera_scan_active {
                        "close"
                    } else {
                        "camera"
                    },
                    if state.peer_invite_camera_scan_active {
                        "Parar leitura"
                    } else {
                        "Escanear QR"
                    },
                    if listener_active {
                        None
                    } else if state.peer_invite_camera_scan_active {
                        Some(Message::StopPeerInviteCameraScan)
                    } else {
                        Some(Message::StartPeerInviteCameraScan)
                    },
                    false
                )
            ]
            .spacing(l.px(6.0)),
            l.label(state.peer_invite_status.clone(), 10.0, MUTED),
            invite_addresses,
            l.label(
                state.peer_verification_status.clone(),
                11.0,
                if state.peer_key_verified { GREEN } else { GOLD }
            ),
            l.control(
                if state.peer_key_verified {
                    "close"
                } else {
                    "check"
                },
                if state.peer_key_verified {
                    "Remover verificação local"
                } else {
                    "Marcar como conferida"
                },
                can_toggle.then_some(Message::TogglePeerVerification),
                state.peer_key_verified
            ),
        ]
        .spacing(l.px(12.0)),
    );
    let instructions = l.panel(
        column![
            l.label("COMO CONFERIR", 10.0, GOLD),
            l.label(
                "Marque como conferida somente depois de autenticar o contato: compare a chave completa por um canal independente ou importe o QR assinado exibido diretamente no dispositivo dele.",
                11.0,
                PAPER
            ),
            l.label(
                "A assinatura vincula os endereços à chave do dispositivo, mas não prova quem enviou uma imagem. Não confie em QR recebido por canal não autenticado. A decisão fica neste perfil e outra chave não herda confiança.",
                10.0,
                MUTED
            ),
            l.control(
                "chat",
                "Voltar ao texto direto",
                Some(Message::Navigate(Screen::Chat)),
                false
            )
        ]
        .spacing(l.px(12.0)),
    );
    let body = column![
        column![
            l.title("Conferir identidade do peer", 32.0),
            l.label(
                "VERIFICAÇÃO MANUAL · CHAVE DO DISPOSITIVO · ARMAZENAMENTO LOCAL",
                10.0,
                VIOLET
            )
        ]
        .spacing(l.px(8.0)),
        row![own, peer].spacing(l.px(16.0)),
        instructions
    ]
    .spacing(l.px(16.0));
    l.place(l.panel(body), 24.0, 80.0, 1232.0, 676.0)
}

fn components(l: Layout) -> Element<'static, Message> {
    let mut colors = column![].spacing(l.px(16.0));
    let tokens = [
        ("Noite", NIGHT),
        ("Painel", PANEL),
        ("Linha", LINE),
        ("Pergaminho", PAPER),
        ("Lanterna", GOLD),
        ("Feitiço", VIOLET),
        ("Musgo", GREEN),
        ("Amanita", RED),
    ];
    for group in tokens.chunks(4) {
        let mut strip = row![].spacing(l.px(10.0));
        for &(name, color) in group {
            strip = strip.push(
                column![
                    container(space())
                        .width(Fill)
                        .height(l.px(54.0))
                        .style(move |_| container::Style {
                            background: Some(color.into()),
                            border: Border {
                                color: LINE,
                                width: 1.0,
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                    l.label(name, 12.0, PAPER)
                ]
                .spacing(l.px(8.0))
                .width(Fill),
            );
        }
        colors = colors.push(strip);
    }
    let left=column![l.title("slouching",62.0),l.label("P2P voice & video for you and your crew",13.0,PAPER),l.label("C O R E S",11.0,MUTED),colors,l.label("T I P O G R A F I A",11.0,MUTED),rule(LINE,1.0),
        row![l.title("Aa",34.0),l.label("Bricolage Grotesque 800 — logo e títulos",11.0,PAPER)].spacing(l.px(16.0)).align_y(iced::Center),rule(LINE,1.0),
        row![l.label("Aa",30.0,PAPER),l.label("JetBrains Mono 400 / 500 / 700",11.0,PAPER)].spacing(l.px(16.0)).align_y(iced::Center),l.label("T E X T U R A",11.0,MUTED),
        l.label("Scanlines, vinheta e painéis translúcidos. Bordas de 1 px e cantos retos preservam o clima da fita VHS.",12.0,MUTED)].spacing(l.px(19.0));
    let mut cast = row![].spacing(l.px(12.0));
    for (art, name) in [
        ("wizards-cutout", "Os Magos"),
        ("frog-cutout", "Sapo Mago"),
        ("gnome-cutout", "Gnomo"),
        ("mushroom-cutout", "O Cogumelo"),
    ] {
        cast = cast.push(
            l.panel(
                column![
                    image(assets().images[art].clone())
                        .width(Fill)
                        .height(l.px(126.0))
                        .content_fit(ContentFit::Contain),
                    l.label(name, 11.0, PAPER)
                ]
                .spacing(l.px(14.0))
                .align_x(iced::Center),
            ),
        );
    }
    let right = column![
        l.label("E L E N C O  ·  F A M I L I A R E S", 11.0, MUTED),
        container(cast).height(l.px(194.0)),
        l.label("C O M P O N E N T E S", 11.0, MUTED),
        row![
            l.control(
                "headphones",
                "Join a Call",
                Some(Message::Navigate(Screen::Lobby)),
                true
            ),
            l.control(
                "users",
                "Create a Call",
                Some(Message::Navigate(Screen::Lobby)),
                false
            )
        ]
        .spacing(l.px(12.0)),
        row![
            l.icon_button(
                "mic",
                Message::PreviewAction("Microfone indisponível nesta prévia.")
            ),
            l.icon_button("screen", Message::Navigate(Screen::Share)),
            l.icon_button("shield", Message::Navigate(Screen::Verify))
        ]
        .spacing(l.px(12.0)),
        l.panel(
            column![
                l.label("CONVITE", 11.0, MUTED),
                field(l, "Nenhum convite gerado"),
                l.label(
                    "Os indicadores de rota, MLS e entrega só serão exibidos com evidência real.",
                    11.0,
                    VIOLET
                )
            ]
            .spacing(l.px(16.0))
        ),
        l.control(
            "screen",
            "Alternar textura VHS",
            Some(Message::ToggleTexture),
            false
        )
    ]
    .spacing(l.px(23.0));
    stack![
        l.place(left, 48.0, 82.0, 520.0, 660.0),
        l.place(right, 608.0, 90.0, 624.0, 640.0)
    ]
    .width(Fill)
    .height(Fill)
    .into()
}

struct Fx;
impl canvas::Program<Message> for Fx {
    type State = ();
    fn draw(
        &self,
        _: &(),
        renderer: &Renderer,
        _: &Theme,
        bounds: Rectangle,
        _: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut f = canvas::Frame::new(renderer, bounds.size());
        for y in (0..bounds.height as usize).step_by(3) {
            f.fill_rectangle(
                Point::new(0.0, y as f32),
                Size::new(bounds.width, 1.0),
                Color::from_rgba(0.0, 0.0, 0.0, 0.14),
            );
        }
        for (start, end) in [
            (Point::ORIGIN, Point::new(bounds.width * 0.15, 0.0)),
            (
                Point::new(bounds.width, 0.0),
                Point::new(bounds.width * 0.85, 0.0),
            ),
        ] {
            let g = canvas::gradient::Linear::new(start, end)
                .add_stop(0.0, Color::from_rgba(0.0, 0.0, 0.0, 0.46))
                .add_stop(1.0, Color::TRANSPARENT);
            f.fill(
                &canvas::Path::rectangle(Point::ORIGIN, bounds.size()),
                canvas::Fill {
                    style: canvas::Style::Gradient(g.into()),
                    ..Default::default()
                },
            );
        }
        vec![f.into_geometry()]
    }
}
