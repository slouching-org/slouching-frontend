use cpal::traits::{DeviceTrait, HostTrait};

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
}
