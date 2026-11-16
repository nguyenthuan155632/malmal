//! TIFF files written anew: the pages of a TIFF, and inks kept as inks.
//!
//! Samples are compressed with Deflate after horizontal prediction, which
//! keeps every bit. Nothing is written but the image: its size, samples,
//! resolution and, for inks, the colour profile that says what they look
//! like.

use std::cell::RefCell;
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::rc::Rc;

use image::DynamicImage;
use tiff::encoder::colortype::{self, ColorType};
use tiff::encoder::compression::DeflateLevel;
use tiff::encoder::{Compression, Predictor, Rational, TiffEncoder, TiffValue};
use tiff::tags::{ExtraSamples, ResolutionUnit, SampleFormat, Tag};

use super::{Deadline, Error, Rebuilt, tif::Picture};
use crate::detect::FileType;
use crate::limits::Limits;

fn encode_error(error: tiff::TiffError) -> Error {
    Error::Encode(error.to_string())
}

/// The file being written, which the encoder does not give back.
#[derive(Clone, Default)]
struct Shared(Rc<RefCell<Cursor<Vec<u8>>>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for Shared {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.0.borrow_mut().seek(to)
    }
}

/// Inks of four channels, then alpha if there is one, 8 or 16 bits a
/// sample, 0 for no ink.
pub(super) enum InkSamples {
    Eight(Vec<u8>),
    Sixteen(Vec<u16>),
}

/// An image of inks kept as inks.
pub(super) struct Kept {
    pub(super) width: u32,
    pub(super) height: u32,
    pub(super) samples: InkSamples,
    /// Alpha after the inks: `Some(true)` if the inks are premultiplied.
    pub(super) alpha: Option<bool>,
    /// The profile the inks print by, written anew.
    pub(super) icc: Option<Vec<u8>>,
    pub(super) density: Option<png::PixelDimensions>,
}

impl Kept {
    /// Turned as Exif orientation `orientation` says.
    pub(super) fn orient(&mut self, orientation: u16) {
        let channels = 4 + usize::from(self.alpha.is_some());
        let (width, height) = (self.width as usize, self.height as usize);
        let turned = matches!(orientation, 5..=8);
        let place = |x: usize, y: usize| -> (usize, usize) {
            match orientation {
                2 => (width - 1 - x, y),
                3 => (width - 1 - x, height - 1 - y),
                4 => (x, height - 1 - y),
                5 => (y, x),
                6 => (height - 1 - y, x),
                7 => (height - 1 - y, width - 1 - x),
                8 => (y, width - 1 - x),
                _ => (x, y),
            }
        };
        let across = if turned { height } else { width };
        fn moved<T: Copy + Default>(
            samples: &[T],
            (width, height, channels, across): (usize, usize, usize, usize),
            place: impl Fn(usize, usize) -> (usize, usize),
        ) -> Vec<T> {
            let mut out = vec![T::default(); samples.len()];
            for y in 0..height {
                for x in 0..width {
                    let (to_x, to_y) = place(x, y);
                    let from = (y * width + x) * channels;
                    let to = (to_y * across + to_x) * channels;
                    out[to..to + channels].copy_from_slice(&samples[from..from + channels]);
                }
            }
            out
        }
        if orientation <= 1 || orientation > 8 {
            return;
        }
        let shape = (width, height, channels, across);
        self.samples = match &self.samples {
            InkSamples::Eight(s) => InkSamples::Eight(moved(s, shape, place)),
            InkSamples::Sixteen(s) => InkSamples::Sixteen(moved(s, shape, place)),
        };
        if turned {
            (self.width, self.height) = (self.height, self.width);
        }
    }
}

/// The pages of a TIFF being written.
pub(super) struct Pages {
    file: Shared,
    encoder: Option<TiffEncoder<Shared>>,
    /// Whether the encoder predicts samples from their neighbours.
    predicting: bool,
    first: Option<(u32, u32)>,
    count: u32,
    most: u64,
}

impl Pages {
    pub(super) fn new(limits: &Limits) -> Result<Self, Error> {
        let file = Shared::default();
        let encoder = TiffEncoder::new(file.clone())
            .map_err(encode_error)?
            .with_compression(Compression::Deflate(DeflateLevel::Balanced));
        Ok(Self {
            file,
            encoder: Some(encoder),
            predicting: false,
            first: None,
            count: 0,
            most: limits.max_decompressed,
        })
    }

    fn page<C: ColorType>(
        &mut self,
        (width, height): (u32, u32),
        samples: &[C::Inner],
        density: Option<png::PixelDimensions>,
        extra: Option<ExtraSamples>,
        icc: Option<&[u8]>,
    ) -> Result<(), Error>
    where
        [C::Inner]: TiffValue,
    {
        // Floating-point samples are not predicted, and the encoder
        // predicts from the wrong neighbour once it is given extra samples.
        let predict = C::SAMPLE_FORMAT[0] != SampleFormat::IEEEFP && extra.is_none();
        if predict != self.predicting {
            let encoder = self.encoder.take().ok_or_else(encode_error_text)?;
            self.encoder = Some(encoder.with_predictor(if predict {
                Predictor::Horizontal
            } else {
                Predictor::None
            }));
            self.predicting = predict;
        }
        let encoder = self.encoder.as_mut().ok_or_else(encode_error_text)?;
        let mut image = encoder
            .new_image::<C>(width, height)
            .map_err(encode_error)?;
        if let Some(extra) = extra {
            image.extra_samples(&[extra]).map_err(encode_error)?;
        }
        if let Some(density) = density.filter(|d| d.unit == png::Unit::Meter) {
            // Dots a centimetre, to a hundredth.
            let per_cm = |v: u32| Rational { n: v, d: 100 };
            image.resolution_unit(ResolutionUnit::Centimeter);
            image.x_resolution(per_cm(density.xppu));
            image.y_resolution(per_cm(density.yppu));
        }
        if let Some(icc) = icc {
            image
                .encoder()
                .write_tag(Tag::IccProfile, icc)
                .map_err(encode_error)?;
        }
        image.write_data(samples).map_err(encode_error)?;
        self.first.get_or_insert((width, height));
        self.count += 1;
        if self.file.0.borrow().get_ref().len() as u64 > self.most {
            return Err(Error::TooLarge);
        }
        Ok(())
    }

    /// Add a page of colours.
    pub(super) fn add(&mut self, picture: &Picture, deadline: Deadline) -> Result<(), Error> {
        deadline.check()?;
        let size = (picture.image.width(), picture.image.height());
        let density = picture.density;
        let alpha = Some(ExtraSamples::UnassociatedAlpha);
        let icc = picture.icc.as_deref();
        match &picture.image {
            DynamicImage::ImageLuma8(i) => {
                self.page::<colortype::Gray8>(size, i.as_raw(), density, None, icc)
            }
            DynamicImage::ImageLuma16(i) => {
                self.page::<colortype::Gray16>(size, i.as_raw(), density, None, icc)
            }
            DynamicImage::ImageLumaA8(i) => {
                self.page::<colortype::Gray8>(size, i.as_raw(), density, alpha, icc)
            }
            DynamicImage::ImageLumaA16(i) => {
                self.page::<colortype::Gray16>(size, i.as_raw(), density, alpha, icc)
            }
            DynamicImage::ImageRgb8(i) => {
                self.page::<colortype::RGB8>(size, i.as_raw(), density, None, icc)
            }
            DynamicImage::ImageRgb16(i) => {
                self.page::<colortype::RGB16>(size, i.as_raw(), density, None, icc)
            }
            DynamicImage::ImageRgba8(i) => {
                self.page::<colortype::RGB8>(size, i.as_raw(), density, alpha, icc)
            }
            DynamicImage::ImageRgba16(i) => {
                self.page::<colortype::RGB16>(size, i.as_raw(), density, alpha, icc)
            }
            // Grey of floating point, which is read as colours of it, is
            // written as grey again.
            DynamicImage::ImageRgb32F(i)
                if icc.is_none() && i.pixels().all(|p| p[0] == p[1] && p[1] == p[2]) =>
            {
                let grey: Vec<f32> = i.pixels().map(|p| p[0]).collect();
                self.page::<colortype::Gray32Float>(size, &grey, density, None, None)
            }
            DynamicImage::ImageRgb32F(i) => {
                self.page::<colortype::RGB32Float>(size, i.as_raw(), density, None, icc)
            }
            DynamicImage::ImageRgba32F(i) => {
                self.page::<colortype::RGB32Float>(size, i.as_raw(), density, alpha, icc)
            }
            other => {
                let rgba = other.to_rgba16();
                self.page::<colortype::RGB16>(size, rgba.as_raw(), density, alpha, icc)
            }
        }
    }

    /// Add a page of inks, with the colour profile they are printed by.
    pub(super) fn add_inks(&mut self, kept: &Kept, deadline: Deadline) -> Result<(), Error> {
        deadline.check()?;
        let size = (kept.width, kept.height);
        let extra = kept.alpha.map(|premultiplied| match premultiplied {
            true => ExtraSamples::AssociatedAlpha,
            false => ExtraSamples::UnassociatedAlpha,
        });
        let icc = kept.icc.as_deref();
        match &kept.samples {
            InkSamples::Eight(s) => {
                self.page::<colortype::CMYK8>(size, s, kept.density, extra, icc)
            }
            InkSamples::Sixteen(s) => {
                self.page::<colortype::CMYK16>(size, s, kept.density, extra, icc)
            }
        }
    }

    pub(super) fn finish(self) -> Result<Rebuilt, Error> {
        let (width, height) = self
            .first
            .ok_or_else(|| Error::Encode("no pages to write".into()))?;
        let count = self.count;
        drop(self.encoder);
        let data = self.file.0.borrow().get_ref().clone();
        Ok(Rebuilt {
            data,
            file_type: FileType::Tiff,
            width,
            height,
            frames: count,
        })
    }
}

fn encode_error_text() -> Error {
    Error::Encode("TIFF encoder is gone".into())
}
