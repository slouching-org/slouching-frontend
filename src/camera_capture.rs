//! Explicit camera enumeration, preview capture, and bounded frame streaming.
//!
//! Camera access is initiated only by the user's preview or share action. Device
//! access and frame conversion run off the Iced thread. On supported desktop
//! platforms, nokhwa selects the native OS camera API.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use nokhwa::{Camera, pixel_format::RgbAFormat, utils::*};

const MAX_PIXELS: usize = 1_920 * 1_080;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraSource {
    pub id: CameraIndex,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct CapturedCameraFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

fn native_backend() -> Result<ApiBackend, String> {
    #[cfg(target_os = "linux")]
    {
        Ok(ApiBackend::Video4Linux)
    }
    #[cfg(target_os = "windows")]
    {
        Ok(ApiBackend::MediaFoundation)
    }
    #[cfg(target_os = "macos")]
    {
        Ok(ApiBackend::AVFoundation)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Err("captura de câmera não está disponível nesta plataforma".to_owned())
    }
}

pub fn enumerate() -> Result<Vec<CameraSource>, String> {
    let backend = native_backend()?;
    nokhwa::query(backend)
        .map_err(|error| format!("não foi possível enumerar câmeras: {error}"))
        .map(|cameras| {
            cameras
                .into_iter()
                .map(|camera| CameraSource {
                    id: camera.index().clone(),
                    name: camera.human_name(),
                })
                .collect()
        })
}

fn open_camera(index: CameraIndex) -> Result<Camera, String> {
    let format = RequestedFormat::new::<RgbAFormat>(RequestedFormatType::HighestFrameRate(15));
    Camera::with_backend(index, format, native_backend()?)
        .map_err(|error| format!("não foi possível abrir a câmera: {error}"))
}

fn capture_next(camera: &mut Camera) -> Result<CapturedCameraFrame, String> {
    let frame = camera
        .frame()
        .map_err(|error| format!("falha ao capturar câmera: {error}"))?;
    let resolution = frame.resolution();
    let width = resolution.width_x;
    let height = resolution.height_y;
    validate_dimensions(width, height)?;
    let decoded = frame
        .decode_image::<RgbAFormat>()
        .map_err(|error| format!("não foi possível converter o quadro da câmera: {error}"))?;
    Ok(CapturedCameraFrame {
        width,
        height,
        rgba: decoded.into_raw(),
    })
}

fn validate_dimensions(width: u32, height: u32) -> Result<(), String> {
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| "dimensões da câmera excedem o limite".to_owned())?;
    if width < 2 || height < 2 || pixels > MAX_PIXELS {
        return Err("dimensões da câmera estão fora do limite permitido".to_owned());
    }
    Ok(())
}

pub fn capture(index: CameraIndex) -> Result<CapturedCameraFrame, String> {
    let mut camera = open_camera(index)?;
    camera
        .open_stream()
        .map_err(|error| format!("permissão ou abertura da câmera falhou: {error}"))?;
    capture_next(&mut camera)
}

/// Start one native capture thread. Dropping the receiver or setting `stop`
/// closes the stream after its current frame and releases the OS camera handle.
pub async fn stream(
    index: CameraIndex,
    stop: Arc<AtomicBool>,
) -> Result<tokio::sync::mpsc::Receiver<Result<CapturedCameraFrame, String>>, String> {
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let mut camera = match open_camera(index) {
            Ok(camera) => camera,
            Err(error) => {
                let _ = ready_sender.send(Err(error.clone()));
                let _ = sender.blocking_send(Err(error));
                return;
            }
        };
        if let Err(error) = camera.open_stream() {
            let error = format!("permissão ou abertura da câmera falhou: {error}");
            let _ = ready_sender.send(Err(error.clone()));
            let _ = sender.blocking_send(Err(error));
            return;
        }
        let _ = ready_sender.send(Ok(()));
        while !stop.load(Ordering::Acquire) {
            match capture_next(&mut camera) {
                Ok(frame) => {
                    if sender.blocking_send(Ok(frame)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.blocking_send(Err(error));
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(66));
        }
        // Dropping `Camera` releases the native stream.
    });
    ready_receiver
        .await
        .map_err(|error| format!("a tarefa de câmera terminou ao inicializar: {error}"))??;
    Ok(receiver)
}

#[cfg(test)]
mod tests {
    use super::validate_dimensions;

    #[test]
    fn camera_capture_accepts_full_hd_and_rejects_invalid_or_unbounded_frames() {
        assert!(validate_dimensions(1920, 1080).is_ok());
        assert!(validate_dimensions(1, 480).is_err());
        assert!(validate_dimensions(3840, 2160).is_err());
    }
}
