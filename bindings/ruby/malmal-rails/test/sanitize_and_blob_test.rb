# frozen_string_literal: true

require "test_helper"

class SanitizeTest < ActiveSupport::TestCase
  include Samples

  setup { Malmal::Rails.config.scan_blobs = false }
  teardown { Malmal::Rails.config.scan_blobs = true }

  test "an attachment is replaced with the file rebuilt from it" do
    user = User.new(avatar: upload(png_with_comment, "me.png", "image/png"))
    assert user.save, user.errors.full_messages.inspect
    stored = user.avatar.download
    assert stored.start_with?("\x89PNG".b)
    refute_includes stored, "holiday"
    assert_equal "me.png", user.avatar.filename.to_s
    assert_equal "image/png", user.avatar.content_type
  end

  test "a type left out of the options is not rebuilt" do
    user = User.new(avatar: upload(corpus("clean/square.svg"), "logo.svg"))
    refute user.valid?, "svg is not among the types"
    assert_equal :malmal_not_rebuilt, user.errors.details[:avatar].first[:error]
  end

  test "an upload that is not clean is refused" do
    user = User.new(avatar: upload(ELF, "me.png"))
    refute user.save
    assert_equal :malmal_malicious, user.errors.details[:avatar].first[:error]
    assert_includes user.errors.details[:avatar].first[:codes], "type.executable"
  end

  test "one that cannot be rebuilt can be kept" do
    pdf = "%PDF-1.7\n1 0 obj\n<< >>\nendobj\ntrailer\n<< >>\n%%EOF\n"
    user = User.new(passport: upload(pdf, "passport.pdf"))
    assert user.valid?, user.errors.full_messages.inspect
    user.save!
    # The library is built without the cdr-pdf feature: a PDF is not rebuilt.
    assert_equal pdf, user.passport.download
  end

  test "every file of a has_many_attached is rebuilt" do
    user = User.create!(photos: [upload(png_with_comment, "a.png"), upload(GIF_WITH_PALETTE, "b.gif")])
    assert_equal(%w[a.png b.gif], user.photos.map { |photo| photo.filename.to_s })
    assert_equal "image/gif", user.photos.last.content_type
    user.photos.each { |photo| refute_includes photo.download, "holiday" }
  end

  test "unknown options are refused" do
    assert_raises(ArgumentError) { User.sanitizes_attachment(:avatar, dpi: 100) }
    assert_raises(ArgumentError) { User.sanitizes_attachment(:avatar, on_not_rebuilt: :ignore) }
  end
end

class BlobScanTest < ActiveSupport::TestCase
  include Samples

  teardown { Malmal::Rails.config.purge_unclean = false }

  test "a stored blob is scanned when it is analyzed" do
    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(ELF), filename: "photo.jpg")
    blob.analyze
    assert_equal "malicious", blob.reload.metadata.dig("malmal", "verdict")
    assert_includes blob.metadata.dig("malmal", "codes"), "type.executable"
    refute blob.malmal_clean?

    clean = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(GIF), filename: "a.gif")
    clean.analyze
    assert clean.reload.malmal_clean?
    assert clean.metadata["analyzed"]
  end

  test "a blob that is not clean can be purged" do
    Malmal::Rails.config.purge_unclean = true
    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(ELF), filename: "photo.jpg")
    blob.analyze
    refute ActiveStorage::Blob.exists?(blob.id)
  end

  test "a blob is scanned even when the analyzer of Active Storage fails" do
    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(ELF), filename: "photo.jpg")
    failing = Class.new(ActiveStorage::Analyzer) do
      def self.accept?(_blob) = true
      def metadata = raise(NameError, "uninitialized constant MiniMagick")
    end
    ActiveStorage.stub(:analyzers, [failing]) do
      assert_raises(NameError) { blob.analyze }
    end
    assert_equal "malicious", blob.reload.metadata.dig("malmal", "verdict")
  end

  test "a blob that was never scanned is neither clean nor not" do
    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(GIF), filename: "a.gif")
    assert_nil blob.malmal_clean?
  end
end

class ConfigTest < ActiveSupport::TestCase
  include Samples

  teardown do
    Malmal::Rails.config.policy = :default
    Malmal::Rails.config.client_url = nil
    Malmal::Rails.reset!
  end

  test "config.malmal is the configuration the scanner is built from" do
    assert_same Rails.application.config.malmal, Malmal::Rails.config
    Malmal::Rails.config.policy = :documents
    Malmal::Rails.reset!
    assert_predicate Malmal::Rails.scanner.scan(FORM, filename: "a.pdf"), :clean?
    assert_equal "documents", Malmal::Rails.scanner.options[:policy]
  end

  test "with client_url, scans go to malmald" do
    Malmal::Rails.config.client_url = "http://127.0.0.1:1"
    Malmal::Rails.reset!
    assert_kind_of Malmal::Client, Malmal::Rails.scanner
    assert_raises(ArgumentError) { Malmal::Rails.scanner_for(policy: :strict) }
  end

  test "the install generator writes an initializer" do
    require "rails/generators"
    require "generators/malmal/install/install_generator"
    Dir.mktmpdir do |dir|
      Malmal::Generators::InstallGenerator.start([], destination_root: dir, quiet: true)
      text = File.read(File.join(dir, "config/initializers/malmal.rb"))
      assert_includes text, "config.malmal.policy = :default"
    end
  end
end
