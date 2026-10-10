//! Explicit desktop monitor enumeration and user-triggered screen capture.
//!
//! Capture calls are blocking and must run outside Iced's UI thread. A captured
//! frame can be shown as a local preview or encoded and sent over an active,
//! end-to-end protected call by the call media layer.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenSource {
    pub id: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowSource {
    pub id: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoSource {
    Monitor(u32),
    Window(u32),
}

#[derive(Debug, Clone)]
pub struct CapturedScreen {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

const MAX_CAPTURE_PIXELS: usize = 7_680 * 4_320;

pub fn enumerate() -> Result<Vec<ScreenSource>, String> {
    xcap::Monitor::all()
        .map_err(|error| format!("não foi possível enumerar telas: {error}"))?
        .into_iter()
        .map(|monitor| {
            Ok(ScreenSource {
                id: monitor.id().map_err(|error| error.to_string())?,
                name: monitor
                    .friendly_name()
                    .or_else(|_| monitor.name())
                    .map_err(|error| error.to_string())?,
                width: monitor.width().map_err(|error| error.to_string())?,
                height: monitor.height().map_err(|error| error.to_string())?,
            })
        })
        .collect()
}

pub fn capture(id: u32) -> Result<CapturedScreen, String> {
    let monitor = xcap::Monitor::all()
        .map_err(|error| format!("não foi possível acessar a tela: {error}"))?
        .into_iter()
        .find(|monitor| monitor.id().ok() == Some(id))
        .ok_or_else(|| "a tela selecionada não está mais disponível".to_owned())?;
    capture_image(monitor.capture_image(), "tela")
}

pub fn enumerate_windows() -> Result<Vec<WindowSource>, String> {
    if uses_wayland_window_portal() {
        return Err(
            "captura de janelas nativas não está disponível em Wayland puro; use uma sessão X11/Xorg ou uma janela executada por XWayland".to_owned(),
        );
    }

    let mut windows = Vec::new();
    for window in xcap::Window::all()
        .map_err(|error| format!("não foi possível enumerar janelas: {error}"))?
    {
        let (Ok(width), Ok(height), Ok(id)) = (window.width(), window.height(), window.id()) else {
            continue;
        };
        if window.is_minimized().unwrap_or(true) || validate_dimensions(width, height).is_err() {
            continue;
        }
        let title = window.title().unwrap_or_default().trim().to_owned();
        let app = window.app_name().unwrap_or_default().trim().to_owned();
        if title.is_empty() && app.is_empty() {
            continue;
        }
        let name = match (app.is_empty(), title.is_empty()) {
            (false, false) => format!("{app} — {title}"),
            (false, true) => app,
            (true, false) => title,
            (true, true) => unreachable!("empty labels were filtered above"),
        };
        windows.push(WindowSource {
            id,
            name,
            width,
            height,
        });
    }
    Ok(windows)
}

pub fn uses_wayland_window_portal() -> bool {
    #[cfg(target_os = "linux")]
    {
        wayland_window_capture_unavailable(
            std::env::var_os("WAYLAND_DISPLAY").is_some(),
            std::env::var_os("DISPLAY").is_some(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub fn capture_video_source(source: VideoSource) -> Result<CapturedScreen, String> {
    match source {
        VideoSource::Monitor(id) => capture(id),
        VideoSource::Window(id) => {
            let window = xcap::Window::all()
                .map_err(|error| format!("não foi possível acessar janelas: {error}"))?
                .into_iter()
                .find(|window| window.id().ok() == Some(id))
                .ok_or_else(|| "a janela selecionada não está mais disponível".to_owned())?;
            capture_image(window.capture_image(), "janela")
        }
    }
}

fn capture_image(
    image: Result<image_codec::RgbaImage, xcap::XCapError>,
    source: &str,
) -> Result<CapturedScreen, String> {
    let image = image.map_err(|error| format!("falha ao capturar {source}: {error}"))?;
    validate_dimensions(image.width(), image.height())?;
    Ok(CapturedScreen {
        width: image.width(),
        height: image.height(),
        rgba: image.into_raw(),
    })
}

pub(crate) fn validate_dimensions(width: u32, height: u32) -> Result<(), String> {
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| "dimensões da captura excedem o limite".to_owned())?;
    if width < 2 || height < 2 || pixels > MAX_CAPTURE_PIXELS {
        return Err("dimensões da captura estão fora do limite permitido".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wayland_window_capture_unavailable(wayland_display: bool, x11_display: bool) -> bool {
    wayland_display && !x11_display
}

#[cfg(test)]
mod tests {
    use super::validate_dimensions;

    #[test]
    fn desktop_capture_bounds_dimensions_before_preview_or_encoding() {
        assert!(validate_dimensions(7680, 4320).is_ok());
        assert!(validate_dimensions(1, 720).is_err());
        assert!(validate_dimensions(7680, 4321).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pure_wayland_reports_x11_window_capture_requirement() {
        assert!(super::wayland_window_capture_unavailable(true, false));
        assert!(!super::wayland_window_capture_unavailable(true, true));
        assert!(!super::wayland_window_capture_unavailable(false, false));
    }
}
