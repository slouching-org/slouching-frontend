use cpal::{
    FromSample, Sample, SampleFormat,
    traits::{DeviceTrait, HostTrait, StreamTrait},
};
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioDevices {
    pub inputs: Vec<AudioDevice>,
    pub outputs: Vec<AudioDevice>,
    pub default_input: Option<String>,
    pub default_output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioDevice {
    pub id: String,
    pub name: String,
}

pub fn choose_device_id(
    current: Option<&str>,
    default: Option<&str>,
    available: &[AudioDevice],
) -> Option<String> {
    current
        .filter(|id| available.iter().any(|device| device.id == *id))
        .or_else(|| default.filter(|id| available.iter().any(|device| device.id == *id)))
        .or_else(|| available.first().map(|device| device.id.as_str()))
        .map(str::to_owned)
}

fn describe(device: &cpal::Device) -> Option<AudioDevice> {
    Some(AudioDevice {
        id: device.id().ok()?.to_string(),
        name: device.description().ok()?.name().to_owned(),
    })
}

pub struct InputMonitor {
    stream: cpal::Stream,
    level_milli: Arc<AtomicU32>,
    error: Arc<Mutex<Option<String>>>,
}

/// Live mono capture from a selected CPAL input. The bounded channel keeps
/// audio callbacks non-blocking; slow consumers drop chunks rather than stall
/// the device thread.
pub struct AudioCapture {
    _stream: cpal::Stream,
    chunks: tokio::sync::mpsc::Receiver<Vec<f32>>,
    sample_rate: u32,
    error: tokio::sync::watch::Receiver<Option<String>>,
}

/// CPAL output backed by a bounded mono queue. A slow device callback emits
/// silence instead of blocking the WebRTC receive task.
pub struct AudioPlayback {
    _stream: cpal::Stream,
    samples: Arc<Mutex<VecDeque<f32>>>,
    error: tokio::sync::watch::Receiver<Option<String>>,
    sample_rate: u32,
}

impl crate::call_audio::AudioSink for AudioPlayback {
    fn push_mono(&self, incoming: &[f32]) {
        AudioPlayback::push_mono(self, incoming);
    }
}

impl AudioPlayback {
    pub fn open(device_id: &str) -> Result<Self, String> {
        let host = cpal::default_host();
        let device = host
            .output_devices()
            .map_err(|error| format!("could not enumerate audio outputs: {error}"))?
            .find(|device| device.id().is_ok_and(|id| id.to_string() == device_id))
            .ok_or_else(|| "selected speaker is no longer available".to_owned())?;
        let supported = device
            .default_output_config()
            .map_err(|error| format!("could not read speaker format: {error}"))?;
        let sample_rate = supported.sample_rate();
        let channels = usize::from(supported.channels());
        let format = supported.sample_format();
        let samples = Arc::new(Mutex::new(VecDeque::with_capacity(48_000)));
        let callback_samples = Arc::clone(&samples);
        let (error_tx, error) = tokio::sync::watch::channel(None);
        let stream = device
            .build_output_stream_raw(
                supported.config(),
                format,
                move |data, _| write_output_data(data, format, channels, &callback_samples),
                move |stream_error| {
                    error_tx.send_replace(Some(stream_error.to_string()));
                },
                None,
            )
            .map_err(|error| format!("could not open speaker: {error}"))?;
        stream
            .play()
            .map_err(|error| format!("could not start speaker: {error}"))?;
        Ok(Self {
            _stream: stream,
            samples,
            error,
            sample_rate,
        })
    }

    pub fn push_mono(&self, incoming: &[f32]) {
        let resampled = resample_mono(incoming, self.sample_rate);
        const MAX_QUEUED_SAMPLES: usize = 96_000;
        if let Ok(mut samples) = self.samples.lock() {
            if samples.len().saturating_add(resampled.len()) > MAX_QUEUED_SAMPLES {
                let excess = samples
                    .len()
                    .saturating_add(resampled.len())
                    .saturating_sub(MAX_QUEUED_SAMPLES);
                let remove = excess.min(samples.len());
                samples.drain(..remove);
            }
            samples.extend(resampled.into_iter().map(|sample| sample.clamp(-1.0, 1.0)));
        }
    }

    pub fn error(&self) -> Option<String> {
        self.error.borrow().clone()
    }
}

fn resample_mono(input: &[f32], output_rate: u32) -> Vec<f32> {
    const INPUT_RATE: u32 = crate::call_audio::SAMPLE_RATE_HZ;
    if input.len() < 2 || output_rate == 0 {
        return Vec::new();
    }
    if output_rate == INPUT_RATE {
        return input.to_vec();
    }
    let output_len = ((input.len() as u64 * u64::from(output_rate) + u64::from(INPUT_RATE) / 2)
        / u64::from(INPUT_RATE)) as usize;
    (0..output_len)
        .map(|index| {
            let position = index as f64 * f64::from(INPUT_RATE) / f64::from(output_rate);
            let left = (position.floor() as usize).min(input.len() - 1);
            let right = (left + 1).min(input.len() - 1);
            let fraction = (position - left as f64) as f32;
            input[left] + (input[right] - input[left]) * fraction
        })
        .collect()
}

fn write_output_data(
    data: &mut cpal::Data,
    format: SampleFormat,
    channels: usize,
    samples: &Arc<Mutex<VecDeque<f32>>>,
) {
    if channels == 0 {
        return;
    }
    macro_rules! write {
        ($sample:ty) => {
            if let Some(output) = data.as_slice_mut::<$sample>() {
                let mut queued = samples.try_lock().ok();
                for frame in output.chunks_exact_mut(channels) {
                    let mono = queued
                        .as_mut()
                        .and_then(|queued| queued.pop_front())
                        .unwrap_or(0.0);
                    for channel in frame {
                        *channel = <$sample>::from_sample(mono);
                    }
                }
            }
        };
    }
    match format {
        SampleFormat::F32 => write!(f32),
        SampleFormat::F64 => write!(f64),
        SampleFormat::I8 => write!(i8),
        SampleFormat::I16 => write!(i16),
        SampleFormat::I24 => write!(cpal::I24),
        SampleFormat::I32 => write!(i32),
        SampleFormat::I64 => write!(i64),
        SampleFormat::U8 => write!(u8),
        SampleFormat::U16 => write!(u16),
        SampleFormat::U24 => write!(cpal::U24),
        SampleFormat::U32 => write!(u32),
        SampleFormat::U64 => write!(u64),
        SampleFormat::DsdU8 | SampleFormat::DsdU16 | SampleFormat::DsdU32 => {}
        _ => {}
    }
}

impl AudioCapture {
    pub fn open(device_id: &str) -> Result<Self, String> {
        let host = cpal::default_host();
        let device = host
            .input_devices()
            .map_err(|error| format!("could not enumerate audio inputs: {error}"))?
            .find(|device| device.id().is_ok_and(|id| id.to_string() == device_id))
            .ok_or_else(|| "selected microphone is no longer available".to_owned())?;
        let supported = device
            .default_input_config()
            .map_err(|error| format!("could not read microphone format: {error}"))?;
        let sample_rate = supported.sample_rate();
        let channels = usize::from(supported.channels());
        let format = supported.sample_format();
        let (chunk_tx, chunks) = tokio::sync::mpsc::channel(16);
        let (error_tx, error) = tokio::sync::watch::channel(None);
        let stream = device
            .build_input_stream_raw(
                supported.config(),
                format,
                move |data, _| {
                    if let Some(mono) = mono_from_data(data, format, channels) {
                        let _ = chunk_tx.try_send(mono);
                    }
                },
                move |stream_error| {
                    error_tx.send_replace(Some(stream_error.to_string()));
                },
                None,
            )
            .map_err(|error| format!("could not open microphone: {error}"))?;
        stream
            .play()
            .map_err(|error| format!("could not start microphone: {error}"))?;
        Ok(Self {
            _stream: stream,
            chunks,
            sample_rate,
            error,
        })
    }

    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    pub async fn next_chunk(&mut self) -> Option<Vec<f32>> {
        self.chunks.recv().await
    }

    pub fn error(&self) -> Option<String> {
        self.error.borrow().clone()
    }
}

fn mono_from_data(data: &cpal::Data, format: SampleFormat, channels: usize) -> Option<Vec<f32>> {
    if channels == 0 {
        return None;
    }
    macro_rules! convert {
        ($sample:ty) => {
            data.as_slice::<$sample>()
                .map(|samples| downmix_samples(samples, channels))
        };
    }
    match format {
        SampleFormat::F32 => convert!(f32),
        SampleFormat::F64 => convert!(f64),
        SampleFormat::I8 => convert!(i8),
        SampleFormat::I16 => convert!(i16),
        SampleFormat::I24 => convert!(cpal::I24),
        SampleFormat::I32 => convert!(i32),
        SampleFormat::I64 => convert!(i64),
        SampleFormat::U8 => convert!(u8),
        SampleFormat::U16 => convert!(u16),
        SampleFormat::U24 => convert!(cpal::U24),
        SampleFormat::U32 => convert!(u32),
        SampleFormat::U64 => convert!(u64),
        SampleFormat::DsdU8 | SampleFormat::DsdU16 | SampleFormat::DsdU32 => None,
        _ => None,
    }
}

fn downmix_samples<T>(samples: &[T], channels: usize) -> Vec<f32>
where
    T: Copy,
    f32: FromSample<T>,
{
    if channels == 0 {
        return Vec::new();
    }
    samples
        .chunks_exact(channels)
        .map(|frame| {
            let sum = frame
                .iter()
                .map(|sample| f32::from_sample(*sample))
                .sum::<f32>();
            (sum / channels as f32).clamp(-1.0, 1.0)
        })
        .collect()
}

impl InputMonitor {
    pub fn open(device_id: &str) -> Result<Self, String> {
        let host = cpal::default_host();
        let device = host
            .input_devices()
            .map_err(|error| format!("could not enumerate audio inputs: {error}"))?
            .find(|device| device.id().is_ok_and(|id| id.to_string() == device_id))
            .ok_or_else(|| "selected microphone is no longer available".to_owned())?;
        let config = device
            .default_input_config()
            .map_err(|error| format!("could not read microphone format: {error}"))?;
        let format = config.sample_format();
        let level_milli = Arc::new(AtomicU32::new(0));
        let callback_level = Arc::clone(&level_milli);
        let error = Arc::new(Mutex::new(None));
        let callback_error = Arc::clone(&error);
        let stream = device
            .build_input_stream_raw(
                config.config(),
                format,
                move |data, _| {
                    if let Some(level) = level_from_data(data, format) {
                        callback_level.store((level * 1000.0) as u32, Ordering::Relaxed);
                    }
                },
                move |stream_error| {
                    if let Ok(mut error) = callback_error.lock() {
                        *error = Some(stream_error.to_string());
                    }
                },
                None,
            )
            .map_err(|error| format!("could not open microphone: {error}"))?;

        Ok(Self {
            stream,
            level_milli,
            error,
        })
    }

    pub fn play(&self) -> Result<(), String> {
        self.stream
            .play()
            .map_err(|error| format!("could not start microphone: {error}"))
    }

    pub fn level(&self) -> f32 {
        self.level_milli.load(Ordering::Relaxed) as f32 / 1000.0
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().ok().and_then(|error| error.clone())
    }
}

fn rms_level<T>(samples: &[T]) -> f32
where
    T: Copy,
    f32: FromSample<T>,
{
    if samples.is_empty() {
        return 0.0;
    }
    let mean_square = samples
        .iter()
        .map(|sample| {
            let sample = f32::from_sample(*sample);
            sample * sample
        })
        .sum::<f32>()
        / samples.len() as f32;
    mean_square.sqrt().clamp(0.0, 1.0)
}

fn level_from_data(data: &cpal::Data, format: SampleFormat) -> Option<f32> {
    macro_rules! samples {
        ($sample:ty) => {
            data.as_slice::<$sample>().map(rms_level::<$sample>)
        };
    }
    match format {
        SampleFormat::F32 => samples!(f32),
        SampleFormat::F64 => samples!(f64),
        SampleFormat::I8 => samples!(i8),
        SampleFormat::I16 => samples!(i16),
        SampleFormat::I24 => samples!(cpal::I24),
        SampleFormat::I32 => samples!(i32),
        SampleFormat::I64 => samples!(i64),
        SampleFormat::U8 => samples!(u8),
        SampleFormat::U16 => samples!(u16),
        SampleFormat::U24 => samples!(cpal::U24),
        SampleFormat::U32 => samples!(u32),
        SampleFormat::U64 => samples!(u64),
        SampleFormat::DsdU8 | SampleFormat::DsdU16 | SampleFormat::DsdU32 => None,
        _ => None,
    }
}

pub fn enumerate_devices() -> Result<AudioDevices, String> {
    let host = cpal::default_host();
    let default_input = host
        .default_input_device()
        .and_then(|device| device.id().ok().map(|device_id| device_id.to_string()));
    let default_output = host
        .default_output_device()
        .and_then(|device| device.id().ok().map(|device_id| device_id.to_string()));
    let inputs = host
        .input_devices()
        .map_err(|error| format!("could not enumerate audio inputs: {error}"))?
        .filter_map(|device| describe(&device))
        .collect();
    let outputs = host
        .output_devices()
        .map_err(|error| format!("could not enumerate audio outputs: {error}"))?
        .filter_map(|device| describe(&device))
        .collect();

    Ok(AudioDevices {
        inputs,
        outputs,
        default_input,
        default_output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, name: &str) -> AudioDevice {
        AudioDevice {
            id: id.to_owned(),
            name: name.to_owned(),
        }
    }

    #[test]
    fn audio_device_selection_keeps_valid_choice_then_falls_back_to_default() {
        let available = [
            device("mic-a", "Microphone A"),
            device("mic-b", "Microphone B"),
        ];
        assert_eq!(
            choose_device_id(Some("mic-a"), Some("mic-b"), &available),
            Some("mic-a".to_owned())
        );
        assert_eq!(
            choose_device_id(Some("removed"), Some("mic-b"), &available),
            Some("mic-b".to_owned())
        );
        assert_eq!(choose_device_id(None, None, &[]), None);
    }

    #[test]
    fn playback_resampler_matches_the_selected_device_sample_rate() {
        let frame = (0..crate::call_audio::FRAME_SAMPLES)
            .map(|index| index as f32 / crate::call_audio::FRAME_SAMPLES as f32)
            .collect::<Vec<_>>();
        let resampled = resample_mono(&frame, 44_100);
        assert_eq!(resampled.len(), 882);
        assert_eq!(resample_mono(&frame, 48_000), frame);
    }

    #[test]
    fn microphone_meter_calculates_bounded_rms_and_silence() {
        assert_eq!(rms_level(&[] as &[f32]), 0.0);
        assert_eq!(rms_level(&[0.5_f32, -0.5_f32]), 0.5);
        assert_eq!(rms_level(&[1.5_f32, -1.5_f32]), 1.0);
    }

    #[test]
    fn capture_downmixes_interleaved_stereo_to_normalized_mono() {
        let mono = downmix_samples(&[0.5_f32, 0.25, -0.5, -0.25], 2);
        assert_eq!(mono, [0.375, -0.375]);
        assert_eq!(downmix_samples(&[1.5_f32, 1.5], 2), [1.0]);
    }
}
