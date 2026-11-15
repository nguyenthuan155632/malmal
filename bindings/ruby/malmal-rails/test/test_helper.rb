# frozen_string_literal: true

require "tmpdir"
require "logger"
require "stringio"
require "zlib"

ENV["RAILS_ENV"] = "test"
ENV["DATABASE_URL"] = "sqlite3::memory:"
require "rails"
require "active_record/railtie"
require "active_job/railtie"
require "active_storage/engine"
require "malmal-rails"
require "minitest/autorun"

ROOT = Dir.mktmpdir("malmal-rails")
Minitest.after_run { FileUtils.remove_entry(ROOT) }

# The smallest application with Active Storage on disk.
class Dummy < Rails::Application
  config.root = ROOT
  config.eager_load = false
  config.logger = Logger.new(nil)
  config.secret_key_base = "0" * 64
  config.active_job.queue_adapter = :inline
  config.active_storage.service = :test
  config.active_storage.service_configurations = { test: { service: "Disk", root: File.join(ROOT, "storage") } }
  config.active_record.maintain_test_schema = false
end

Rails.application.initialize!

ActiveRecord::Schema.verbose = false
ActiveRecord::Schema.define do
  create_table :active_storage_blobs do |t|
    t.string :key, null: false
    t.string :filename, null: false
    t.string :content_type
    t.text :metadata
    t.string :service_name, null: false
    t.bigint :byte_size, null: false
    t.string :checksum
    t.datetime :created_at, null: false
    t.index [:key], unique: true
  end
  create_table :active_storage_attachments do |t|
    t.string :name, null: false
    t.references :record, null: false, polymorphic: true, index: false
    t.references :blob, null: false
    t.datetime :created_at, null: false
    t.index %i[record_type record_id name blob_id], unique: true, name: "index_attachments_uniqueness"
  end
  create_table :active_storage_variant_records do |t|
    t.belongs_to :blob, null: false, index: false
    t.string :variation_digest, null: false
  end
  create_table :documents do |t|
    t.string :title
  end
  create_table :users do |t|
    t.string :name
  end
end

class Document < ActiveRecord::Base
  has_one_attached :file
  has_many_attached :pages
  validates :file, malmal: true
  validates :pages, malmal: { policy: :documents }
end

class User < ActiveRecord::Base
  has_one_attached :avatar
  has_many_attached :photos
  has_one_attached :passport
  sanitizes_attachment :avatar, :photos, types: %i[png jpeg gif]
  sanitizes_attachment :passport, on_not_rebuilt: :keep
end

module Samples
  CORPUS = File.expand_path("../../../../tests/corpus", __dir__)
  GIF = "GIF89a\x01\x00\x01\x00\x00\x00\x00\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4C\x01\x00\x3B".b
  # One white pixel, with a colour table, which a decoder needs.
  GIF_WITH_PALETTE = "GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff" \
                     ",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;".b
  ELF = "\x7fELF\x02\x01\x01#{"\0" * 9}".b
  FORM = "%PDF-1.7\n1 0 obj << /Type /Catalog /AcroForm << /XFA 2 0 R >> >> endobj\n" \
         "2 0 obj << /Length 0 >> stream\n\nendstream endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"

  module_function

  def corpus(path)
    File.binread(File.join(CORPUS, path))
  end

  def upload(data, filename, content_type = nil)
    { io: StringIO.new(data), filename: filename, content_type: content_type }
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
