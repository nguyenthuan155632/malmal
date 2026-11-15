# frozen_string_literal: true

# MALMAL_TEST_INSTALLED=1 tests the gem as installed, library and all.
$LOAD_PATH.unshift File.expand_path("../lib", __dir__) unless ENV["MALMAL_TEST_INSTALLED"] == "1"
require "malmal"
require "minitest/autorun"
require "digest"
require "zlib"

module Samples
  CORPUS = File.expand_path("../../../../tests/corpus", __dir__)

  GIF = "GIF89a\x01\x00\x01\x00\x00\x00\x00\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4C\x01\x00\x3B".b
  ELF = "\x7fELF\x02\x01\x01#{"\0" * 9}".b
  FORM = "%PDF-1.7\n1 0 obj << /Type /Catalog /AcroForm << /XFA 2 0 R >> >> endobj\n" \
         "2 0 obj << /Length 0 >> stream\n\nendstream endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"

  module_function

  def corpus(path)
    File.binread(File.join(CORPUS, path))
  end

  # One transparent pixel, and a comment a rebuilt file does not keep.
  def png_with_comment
    chunk = lambda do |kind, body|
      [body.bytesize].pack("N") + kind + body + [Zlib.crc32(kind + body)].pack("N")
    end
    "\x89PNG\r\n\x1a\n".b +
      chunk.call("IHDR", [1, 1, 8, 6, 0, 0, 0].pack("NNCCCCC")) +
      chunk.call("tEXt", "Comment\0taken on holiday") +
      chunk.call("IDAT", Zlib::Deflate.deflate("\0" * 5)) +
      chunk.call("IEND", "")
  end
end
