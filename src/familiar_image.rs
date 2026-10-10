use std::io::{Cursor, Read};
use std::path::Path;

const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_INPUT_DIMENSION: u32 = 4096;
const MAX_OUTPUT_BYTES: usize = 512 * 1024;
const OUTPUT_EDGE: u32 = 256;

pub fn load_png(path: &Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("Não foi possível consultar o PNG: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Não foi possível consultar o PNG: {error}"))?;
    if metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err("Escolha um PNG de até 8 MiB.".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Não foi possível ler o PNG: {error}"))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err("Escolha um PNG de até 8 MiB.".to_owned());
    }
    normalize_png(&bytes)
}

pub fn normalize_png(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.is_empty() || bytes.len() > MAX_INPUT_BYTES {
        return Err("Escolha um PNG de até 8 MiB.".to_owned());
    }
    let reader =
        image_codec::ImageReader::with_format(Cursor::new(bytes), image_codec::ImageFormat::Png);
    let (width, height) = reader
        .into_dimensions()
        .map_err(|_| "Não foi possível ler as dimensões do PNG.".to_owned())?;
    if width == 0
        || height == 0
        || width > MAX_INPUT_DIMENSION
        || height > MAX_INPUT_DIMENSION
        || u64::from(width) * u64::from(height)
            > u64::from(MAX_INPUT_DIMENSION) * u64::from(MAX_INPUT_DIMENSION)
    {
        return Err("A imagem precisa ter no máximo 4096 × 4096 pixels.".to_owned());
    }

    let decoded = image_codec::load_from_memory_with_format(bytes, image_codec::ImageFormat::Png)
        .map_err(|_| "O arquivo selecionado não é um PNG válido.".to_owned())?;
    let resized = decoded.thumbnail(OUTPUT_EDGE, OUTPUT_EDGE).to_rgba8();
    let mut output = Cursor::new(Vec::new());
    image_codec::DynamicImage::ImageRgba8(resized)
        .write_to(&mut output, image_codec::ImageFormat::Png)
        .map_err(|_| "Não foi possível preparar a imagem do familiar.".to_owned())?;
    let normalized = output.into_inner();
    if normalized.len() > MAX_OUTPUT_BYTES {
        return Err("A imagem otimizada ultrapassa o limite local de 512 KiB.".to_owned());
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image_codec::GenericImageView;

    #[test]
    fn normalized_avatar_is_small_png_with_bounded_dimensions() {
        let image =
            image_codec::RgbaImage::from_pixel(800, 400, image_codec::Rgba([32, 64, 96, 255]));
        let mut encoded = Cursor::new(Vec::new());
        image_codec::DynamicImage::ImageRgba8(image)
            .write_to(&mut encoded, image_codec::ImageFormat::Png)
            .unwrap();

        let normalized = normalize_png(encoded.get_ref()).unwrap();
        let decoded =
            image_codec::load_from_memory_with_format(&normalized, image_codec::ImageFormat::Png)
                .unwrap();
        assert_eq!(decoded.dimensions(), (256, 128));
        assert!(normalized.len() <= MAX_OUTPUT_BYTES);
    }

    #[test]
    fn rejects_invalid_or_oversized_avatar_files() {
        assert!(normalize_png(b"not a png").is_err());
        assert!(normalize_png(&vec![0; MAX_INPUT_BYTES + 1]).is_err());
    }
}
