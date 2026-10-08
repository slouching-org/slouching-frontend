use iced::widget::{button, column, container, image, row, text, text_input};
use iced::{Color, Element, Fill, Length, Theme};

#[derive(Debug, Clone, Copy, Default)]
enum Screen {
    #[default]
    Home,
    Familiar,
    Call,
}

struct Slouching {
    screen: Screen,
    invite: String,
    name: String,
    familiar: &'static str,
    notice: String,
}

impl Default for Slouching {
    fn default() -> Self {
        Self {
            screen: Screen::Home,
            invite: String::new(),
            name: String::new(),
            familiar: "Wizard",
            notice: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    Navigate(Screen),
    InviteChanged(String),
    NameChanged(String),
    ChooseFamiliar(&'static str),
    Join,
    Create,
    PreviewControl,
}

fn update(state: &mut Slouching, message: Message) {
    match message {
        Message::Navigate(screen) => {
            state.screen = screen;
            state.notice.clear();
        }
        Message::InviteChanged(value) => state.invite = value,
        Message::NameChanged(value) => state.name = value,
        Message::ChooseFamiliar(value) => state.familiar = value,
        Message::Join => {
            state.notice = if state.invite.trim().is_empty() {
                "Paste an invitation when the peer protocol is ready.".into()
            } else {
                "Invitations are not processed yet. Nothing was sent.".into()
            };
        }
        Message::Create => {
            state.notice = "Group creation is not implemented yet.".into();
        }
        Message::PreviewControl => {
            state.notice = "Visual preview only. No device or peer was connected.".into();
        }
    }
}

fn view(state: &Slouching) -> Element<'_, Message> {
    let navigation = row![
        button("Home").on_press(Message::Navigate(Screen::Home)),
        button("Familiar").on_press(Message::Navigate(Screen::Familiar)),
        button("Call preview").on_press(Message::Navigate(Screen::Call)),
    ]
    .spacing(12);

    let page = match state.screen {
        Screen::Home => home(state),
        Screen::Familiar => familiar(state),
        Screen::Call => call(state),
    };

    container(
        column![
            navigation,
            page,
            text("LOCAL NATIVE SCAFFOLD · NO CONNECTION · NO CRYPTOGRAPHY")
                .size(12)
                .color(Color::from_rgb8(180, 140, 255)),
        ]
        .spacing(20),
    )
    .padding(24)
    .width(Fill)
    .height(Fill)
    .into()
}

fn home(state: &Slouching) -> Element<'_, Message> {
    let logo = image(image::Handle::from_bytes(
        include_bytes!("../prototypes/web/brand/05-two-wizards-primary-logo.png").to_vec(),
    ))
    .width(Length::Fixed(80.0))
    .height(Length::Fixed(80.0));
    let scenery = image(image::Handle::from_bytes(
        include_bytes!("../prototypes/web/art/bg-home.jpg").to_vec(),
    ))
    .width(Length::Fill)
    .height(Length::Fixed(350.0));

    column![
        row![
            logo,
            text("slouching")
                .size(68)
                .color(Color::from_rgb8(242, 223, 138)),
        ]
        .spacing(16),
        text("P2P voice & video for you and your crew")
            .size(17)
            .color(Color::from_rgb8(236, 230, 255)),
        row![
            button("Join a call").on_press(Message::Join),
            button("Create a call").on_press(Message::Create),
        ]
        .spacing(12),
        text_input("slouch:// invitation", &state.invite)
            .on_input(Message::InviteChanged)
            .on_submit(Message::Join),
        text(&state.notice).color(Color::from_rgb8(242, 223, 138)),
        scenery,
    ]
    .spacing(15)
    .into()
}

fn familiar(state: &Slouching) -> Element<'_, Message> {
    column![
        text("Who sits by the campfire?")
            .size(38)
            .color(Color::from_rgb8(242, 223, 138)),
        text("Choose a preview name and familiar. No cryptographic identity is created."),
        text_input("Your name", &state.name).on_input(Message::NameChanged),
        row![
            button("Wizard").on_press(Message::ChooseFamiliar("Wizard")),
            button("Frog").on_press(Message::ChooseFamiliar("Frog")),
            button("Orb").on_press(Message::ChooseFamiliar("Orb")),
        ]
        .spacing(12),
        text(format!("Selected familiar: {}", state.familiar)),
    ]
    .spacing(18)
    .into()
}

fn call(state: &Slouching) -> Element<'_, Message> {
    let art = image(image::Handle::from_bytes(
        include_bytes!("../prototypes/web/art/scene-orb.jpg").to_vec(),
    ))
    .width(Length::Fill)
    .height(Length::Fixed(390.0));

    column![
        text("THE MOSSY STUMP · CALL PREVIEW")
            .size(28)
            .color(Color::from_rgb8(242, 223, 138)),
        text("Illustrative art. No participant or video stream is connected.")
            .color(Color::from_rgb8(180, 140, 255)),
        art,
        row![
            button("Microphone").on_press(Message::PreviewControl),
            button("Camera").on_press(Message::PreviewControl),
            button("Share screen").on_press(Message::PreviewControl),
            button("Leave preview").on_press(Message::Navigate(Screen::Home)),
        ]
        .spacing(12),
        text(&state.notice).color(Color::from_rgb8(242, 223, 138)),
    ]
    .spacing(16)
    .into()
}

fn main() -> iced::Result {
    iced::application(Slouching::default, update, view)
        .theme(Theme::Dark)
        .window_size((1000.0, 800.0))
        .run()
}
