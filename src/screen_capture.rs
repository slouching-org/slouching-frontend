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

#[derive(Debug, Clone)]
pub struct CapturedScreen {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

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
    let image = monitor
        .capture_image()
        .map_err(|error| format!("falha ao capturar a tela: {error}"))?;
    Ok(CapturedScreen {
        width: image.width(),
        height: image.height(),
        rgba: image.into_raw(),
    })
}
