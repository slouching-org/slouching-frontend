use crate::screen_capture::{CapturedScreen, validate_dimensions};
use ashpd::desktop::{
    PersistMode,
    screencast::{CursorMode, Screencast, SourceType},
};
use pipewire as pw;
use pw::{properties::properties, spa, spa::pod::Pod};
use std::{
    fmt::Display,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

const MAX_FRAME_BYTES: usize = 7680 * 4320 * 4;

pub struct WaylandWindowCapture {
    frames: mpsc::Receiver<Result<CapturedScreen, String>>,
    stop: Arc<AtomicBool>,
    supervisor: JoinHandle<()>,
}

impl WaylandWindowCapture {
    pub async fn start(stop: Arc<AtomicBool>) -> Result<Self, String> {
        pw::init();
        let (frame_tx, frames) = mpsc::channel(2);
        let (ready_tx, ready_rx) = oneshot::channel();
        let supervisor = tokio::spawn(run_portal_session(frame_tx, ready_tx, Arc::clone(&stop)));
        match ready_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = supervisor.await;
                return Err(error);
            }
            Err(_) => return Err("a sessão do portal de captura foi encerrada".to_owned()),
        }

        Ok(Self {
            frames,
            stop,
            supervisor,
        })
    }

    pub async fn recv(&mut self) -> Option<Result<CapturedScreen, String>> {
        self.frames.recv().await
    }

    pub async fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), &mut self.supervisor).await;
    }
}

impl Drop for WaylandWindowCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

async fn run_portal_session(
    frames: mpsc::Sender<Result<CapturedScreen, String>>,
    ready: oneshot::Sender<Result<(), String>>,
    stop: Arc<AtomicBool>,
) {
    let proxy = match cancellable_portal_call(&stop, Screencast::new()).await {
        Ok(proxy) => proxy,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "não foi possível acessar o portal de captura: {error}"
            )));
            return;
        }
    };
    let available = match cancellable_portal_call(&stop, proxy.available_source_types()).await {
        Ok(types) => types,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "não foi possível consultar o portal de captura: {error}"
            )));
            return;
        }
    };
    if !available.contains(SourceType::Window) {
        let _ = ready.send(Err(
            "o portal do desktop não oferece seleção de janelas nesta sessão".to_owned(),
        ));
        return;
    }
    let cursor_modes = match cancellable_portal_call(&stop, proxy.available_cursor_modes()).await {
        Ok(modes) => modes,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "não foi possível consultar o cursor do portal: {error}"
            )));
            return;
        }
    };
    let cursor_mode = if cursor_modes.contains(CursorMode::Embedded) {
        CursorMode::Embedded
    } else if cursor_modes.contains(CursorMode::Hidden) {
        CursorMode::Hidden
    } else {
        let _ = ready.send(Err(
            "o portal do desktop não oferece um modo de cursor compatível".to_owned(),
        ));
        return;
    };
    let session = match cancellable_portal_call(&stop, proxy.create_session()).await {
        Ok(session) => session,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "não foi possível criar a sessão do portal: {error}"
            )));
            return;
        }
    };
    let selected = cancellable_portal_call(
        &stop,
        proxy.select_sources(
            &session,
            cursor_mode,
            SourceType::Window.into(),
            false,
            None,
            PersistMode::DoNot,
        ),
    )
    .await;
    match selected {
        Ok(request) => match request.response() {
            Ok(()) => {}
            Err(error) => {
                let _ = ready.send(Err(format!(
                    "o portal recusou a seleção de janelas: {error}"
                )));
                let _ = session.close().await;
                return;
            }
        },
        Err(error) => {
            let _ = ready.send(Err(format!(
                "não foi possível preparar o seletor de janelas: {error}"
            )));
            let _ = session.close().await;
            return;
        }
    }
    let streams = match cancellable_portal_call(&stop, proxy.start(&session, None)).await {
        Ok(request) => match request.response() {
            Ok(streams) => streams,
            Err(error) => {
                let _ = ready.send(Err(format!("a seleção de janela foi cancelada: {error}")));
                let _ = session.close().await;
                return;
            }
        },
        Err(error) => {
            let _ = ready.send(Err(format!(
                "não foi possível abrir o seletor de janelas: {error}"
            )));
            let _ = session.close().await;
            return;
        }
    };
    let Some(stream) = streams.streams().first() else {
        let _ = ready.send(Err(
            "o portal não retornou uma janela para capturar".to_owned()
        ));
        let _ = session.close().await;
        return;
    };
    if stream.source_type() != Some(SourceType::Window) {
        let _ = ready.send(Err(
            "o portal retornou uma fonte que não é uma janela".to_owned()
        ));
        let _ = session.close().await;
        return;
    }
    let node_id = stream.pipe_wire_node_id();
    let remote = match cancellable_portal_call(&stop, proxy.open_pipe_wire_remote(&session)).await {
        Ok(remote) => remote,
        Err(error) => {
            let _ = ready.send(Err(format!(
                "não foi possível abrir o fluxo PipeWire: {error}"
            )));
            let _ = session.close().await;
            return;
        }
    };
    let worker_stop = Arc::clone(&stop);
    let worker_frames = frames.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        let result = run_pipewire_capture(remote, node_id, worker_frames.clone(), worker_stop);
        if let Err(error) = &result {
            let _ = worker_frames.try_send(Err(error.clone()));
        }
        result
    });
    if ready.send(Ok(())).is_err() {
        stop.store(true, Ordering::Release);
    }
    tokio::select! {
        _ = wait_until_stopped(Arc::clone(&stop)) => {
            stop.store(true, Ordering::Release);
            let _ = worker.await;
        }
        result = &mut worker => {
            if let Err(error) = result {
                let _ = frames.try_send(Err(format!("worker PipeWire falhou: {error}")));
            }
        }
    }
    let _ = session.close().await;
}

async fn wait_until_stopped(stop: Arc<AtomicBool>) {
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

async fn cancellable_portal_call<T, E, F>(stop: &Arc<AtomicBool>, future: F) -> Result<T, String>
where
    E: Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        result = future => result.map_err(|error| error.to_string()),
        _ = wait_until_stopped(Arc::clone(stop)) => Err("captura cancelada".to_owned()),
    }
}

#[derive(Default)]
struct PipeWireCaptureState {
    format: spa::param::video::VideoInfoRaw,
    frames: Option<mpsc::Sender<Result<CapturedScreen, String>>>,
    stop: Option<Arc<AtomicBool>>,
    mainloop: Option<pw::main_loop::MainLoopRc>,
}

fn run_pipewire_capture(
    remote: std::os::fd::OwnedFd,
    node_id: u32,
    frames: mpsc::Sender<Result<CapturedScreen, String>>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let mainloop = pw::main_loop::MainLoopRc::new(None)
        .map_err(|error| format!("falha ao criar o loop PipeWire: {error}"))?;
    let context = pw::context::ContextRc::new(&mainloop, None)
        .map_err(|error| format!("falha ao criar o contexto PipeWire: {error}"))?;
    let core = context
        .connect_fd_rc(remote, None)
        .map_err(|error| format!("falha ao conectar o fluxo PipeWire: {error}"))?;
    let stream = pw::stream::StreamRc::new(
        core,
        "slouching-window-capture",
        properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )
    .map_err(|error| format!("falha ao criar o fluxo PipeWire: {error}"))?;
    let stop_for_listener = Arc::clone(&stop);
    let loop_for_listener = mainloop.clone();
    let _listener = stream
        .add_local_listener_with_user_data(PipeWireCaptureState {
            frames: Some(frames),
            stop: Some(stop_for_listener),
            mainloop: Some(loop_for_listener),
            ..PipeWireCaptureState::default()
        })
        .param_changed(|_, state, id, param| {
            let Some(param) = param else {
                return;
            };
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Ok((media_type, media_subtype)) = spa::param::format_utils::parse_format(param)
            else {
                return;
            };
            if media_type != spa::param::format::MediaType::Video
                || media_subtype != spa::param::format::MediaSubtype::Raw
            {
                return;
            }
            if state.format.parse(param).is_err() {
                if let Some(sender) = &state.frames {
                    let _ = sender.try_send(Err("formato PipeWire de vídeo inválido".to_owned()));
                }
                if let Some(stop) = &state.stop {
                    stop.store(true, Ordering::Release);
                }
                return;
            }
            let format = state.format.format();
            if !matches!(
                format,
                spa::param::video::VideoFormat::RGBA
                    | spa::param::video::VideoFormat::RGBx
                    | spa::param::video::VideoFormat::BGRA
                    | spa::param::video::VideoFormat::BGRx
            ) {
                if let Some(sender) = &state.frames {
                    let _ = sender.try_send(Err(format!(
                        "o portal forneceu formato de pixel não suportado: {format:?}"
                    )));
                }
                if let Some(stop) = &state.stop {
                    stop.store(true, Ordering::Release);
                }
                return;
            }
            let size = state.format.size();
            if validate_dimensions(size.width, size.height).is_err() {
                if let Some(sender) = &state.frames {
                    let _ = sender.try_send(Err(
                        "o portal retornou dimensões de vídeo fora do limite permitido".to_owned(),
                    ));
                }
                if let Some(stop) = &state.stop {
                    stop.store(true, Ordering::Release);
                }
            }
        })
        .process(|stream, state| {
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            if state
                .stop
                .as_ref()
                .is_some_and(|stop| stop.load(Ordering::Acquire))
            {
                if let Some(mainloop) = &state.mainloop {
                    mainloop.quit();
                }
                return;
            }
            let size = state.format.size();
            if size.width == 0 || size.height == 0 {
                return;
            }
            let width = size.width;
            let height = size.height;
            let format = state.format.format();
            let Some(data) = buffer.datas_mut().first_mut() else {
                return;
            };
            let chunk = data.chunk();
            let offset = chunk.offset() as usize;
            let byte_count = chunk.size() as usize;
            let stride = chunk.stride();
            let Some(bytes) = data.data() else {
                return;
            };
            let frame = copy_video_frame(format, width, height, stride, offset, byte_count, bytes);
            match frame {
                Ok(frame) => {
                    if let Some(sender) = &state.frames
                        && sender.try_send(Ok(frame)).is_err()
                        && sender.is_closed()
                        && let Some(mainloop) = &state.mainloop
                    {
                        mainloop.quit();
                    }
                }
                Err(error) => {
                    if let Some(sender) = &state.frames {
                        let _ = sender.try_send(Err(error));
                    }
                    if let Some(stop) = &state.stop {
                        stop.store(true, Ordering::Release);
                    }
                }
            }
        })
        .register()
        .map_err(|error| format!("falha ao registrar o fluxo PipeWire: {error}"))?;

    let format_bytes = rgba_video_format_pod();
    let pod =
        Pod::from_bytes(&format_bytes).ok_or_else(|| "formato PipeWire inválido".to_owned())?;
    let mut params = [pod];
    stream
        .connect(
            spa::utils::Direction::Input,
            Some(node_id),
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .map_err(|error| format!("falha ao conectar a janela selecionada: {error}"))?;

    let loop_for_timer = mainloop.clone();
    let stop_for_timer = Arc::clone(&stop);
    let timer = mainloop.loop_().add_timer(move |_| {
        if stop_for_timer.load(Ordering::Acquire) {
            loop_for_timer.quit();
        }
    });
    timer
        .update_timer(
            Some(std::time::Duration::from_millis(50)),
            Some(std::time::Duration::from_millis(50)),
        )
        .into_sync_result()
        .map_err(|error| format!("falha ao iniciar o timer PipeWire: {error}"))?;
    mainloop.run();
    Ok(())
}

fn rgba_video_format_pod() -> Vec<u8> {
    let object = spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaType,
            Id,
            spa::param::format::MediaType::Video
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaSubtype,
            Id,
            spa::param::format::MediaSubtype::Raw
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            spa::param::video::VideoFormat::RGBA,
            spa::param::video::VideoFormat::RGBA,
            spa::param::video::VideoFormat::RGBx,
            spa::param::video::VideoFormat::BGRA,
            spa::param::video::VideoFormat::BGRx
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            spa::utils::Rectangle {
                width: 1920,
                height: 1080
            },
            spa::utils::Rectangle {
                width: 2,
                height: 2
            },
            spa::utils::Rectangle {
                width: 7680,
                height: 4320
            }
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            spa::utils::Fraction { num: 5, denom: 1 },
            spa::utils::Fraction { num: 1, denom: 1 },
            spa::utils::Fraction { num: 30, denom: 1 }
        ),
    );
    spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(object),
    )
    .expect("serialize fixed PipeWire video format")
    .0
    .into_inner()
}

fn copy_rgba_frame(
    width: u32,
    height: u32,
    stride: i32,
    offset: usize,
    byte_count: usize,
    buffer: &[u8],
) -> Result<CapturedScreen, String> {
    validate_dimensions(width, height)?;
    let row_bytes = (width as usize)
        .checked_mul(4)
        .ok_or_else(|| "quadro PipeWire excede o tamanho permitido".to_owned())?;
    let stride = usize::try_from(stride)
        .map_err(|_| "stride PipeWire inválido para quadro RGBA".to_owned())?;
    if stride < row_bytes {
        return Err("stride PipeWire é menor que a linha RGBA".to_owned());
    }
    let frame_bytes = row_bytes
        .checked_mul(height as usize)
        .ok_or_else(|| "quadro PipeWire excede o tamanho permitido".to_owned())?;
    let span = stride
        .checked_mul(height.saturating_sub(1) as usize)
        .and_then(|last| last.checked_add(row_bytes))
        .ok_or_else(|| "quadro PipeWire excede o tamanho permitido".to_owned())?;
    let end = offset
        .checked_add(byte_count)
        .ok_or_else(|| "quadro PipeWire excede o tamanho permitido".to_owned())?;
    if frame_bytes > MAX_FRAME_BYTES || span > byte_count || end > buffer.len() {
        return Err("dados PipeWire incompletos para o quadro RGBA".to_owned());
    }
    let mut rgba = Vec::with_capacity(frame_bytes);
    for row in 0..height as usize {
        let start = offset + row * stride;
        rgba.extend_from_slice(&buffer[start..start + row_bytes]);
    }
    Ok(CapturedScreen {
        width,
        height,
        rgba,
    })
}

fn copy_video_frame(
    format: spa::param::video::VideoFormat,
    width: u32,
    height: u32,
    stride: i32,
    offset: usize,
    byte_count: usize,
    buffer: &[u8],
) -> Result<CapturedScreen, String> {
    let mut frame = copy_rgba_frame(width, height, stride, offset, byte_count, buffer)?;
    match format {
        spa::param::video::VideoFormat::RGBA => Ok(frame),
        spa::param::video::VideoFormat::RGBx => {
            for pixel in frame.rgba.chunks_exact_mut(4) {
                pixel[3] = 255;
            }
            Ok(frame)
        }
        spa::param::video::VideoFormat::BGRA => {
            for pixel in frame.rgba.chunks_exact_mut(4) {
                pixel.swap(0, 2);
            }
            Ok(frame)
        }
        spa::param::video::VideoFormat::BGRx => {
            for pixel in frame.rgba.chunks_exact_mut(4) {
                pixel.swap(0, 2);
                pixel[3] = 255;
            }
            Ok(frame)
        }
        _ => Err("formato de pixel PipeWire não suportado".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_rgba_frame, copy_video_frame};

    #[test]
    fn pipewire_rgba_copy_removes_row_padding_and_checks_bounds() {
        let data = [
            1, 2, 3, 4, 5, 6, 7, 8, 99, 99, 9, 10, 11, 12, 13, 14, 15, 16, 99, 99,
        ];
        let frame = copy_rgba_frame(2, 2, 10, 0, 20, &data).unwrap();
        assert_eq!(frame.rgba, (1..=16).collect::<Vec<u8>>());
        assert!(copy_rgba_frame(2, 2, 7, 0, 16, &data).is_err());
        assert!(copy_rgba_frame(2, 2, 8, 5, 15, &data).is_err());
    }

    #[test]
    fn pipewire_bgrx_is_converted_to_rgba_with_opaque_alpha() {
        let data = [3, 2, 1, 0, 30, 20, 10, 0, 6, 5, 4, 0, 60, 50, 40, 0];
        let frame = copy_video_frame(
            pipewire::spa::param::video::VideoFormat::BGRx,
            2,
            2,
            8,
            0,
            16,
            &data,
        )
        .unwrap();
        assert_eq!(
            frame.rgba,
            [1, 2, 3, 255, 10, 20, 30, 255, 4, 5, 6, 255, 40, 50, 60, 255]
        );
    }
}
