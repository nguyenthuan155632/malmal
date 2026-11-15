# frozen_string_literal: true

require "test_helper"
require "rack/test"

class ValidatorTest < ActiveSupport::TestCase
  include Samples

  setup do
    Malmal::Rails.config.scan_blobs = false
    @events = []
    @subscriber = ActiveSupport::Notifications.subscribe("scan.malmal") { |*, payload| @events << payload }
  end

  teardown do
    ActiveSupport::Notifications.unsubscribe(@subscriber)
    Malmal::Rails.config.scan_blobs = true
  end

  test "a clean upload is accepted and stored" do
    document = Document.new(file: upload(GIF, "a.gif", "image/gif"))
    assert document.save, document.errors.full_messages.inspect
    assert_equal GIF, document.file.download
    assert_equal "a.gif", @events.last[:filename]
    assert_predicate @events.last[:report], :clean?
  end

  test "a malicious upload is refused before it is stored" do
    blobs = ActiveStorage::Blob.count
    document = Document.new(file: upload(ELF, "photo.jpg", "image/jpeg"))
    refute document.save
    detail = document.errors.details[:file].first
    assert_equal :malmal_malicious, detail[:error]
    assert_includes detail[:codes], "type.executable"
    assert_equal "photo.jpg", detail[:filename]
    assert_equal ["File could not be accepted: photo.jpg looks malicious"], document.errors.full_messages
    assert_equal blobs, ActiveStorage::Blob.count
  end

  test "an uploaded file from a form is read from its tempfile" do
    Tempfile.create(["upload", ".png"]) do |tempfile|
      tempfile.binmode
      tempfile.write(ELF)
      tempfile.rewind
      file = Rack::Test::UploadedFile.new(tempfile.path, "image/png", true, original_filename: "x.png")
      document = Document.new(file: file)
      refute document.valid?
      assert_equal :malmal_malicious, document.errors.details[:file].first[:error]
    end
  end

  test "a direct upload is read back from the service" do
    blob = ActiveStorage::Blob.create_and_upload!(io: StringIO.new(ELF), filename: "photo.jpg")
    document = Document.new(file: blob.signed_id)
    refute document.valid?
    assert_equal :malmal_malicious, document.errors.details[:file].first[:error]
  end

  test "attachments the record already has are not scanned again" do
    document = Document.create!(file: upload(GIF, "a.gif"))
    @events.clear
    document.update!(title: "renamed")
    assert_empty @events
  end

  test "a validator can ask for its own policy" do
    document = Document.new(pages: [upload(FORM, "form.pdf", "application/pdf")])
    assert document.valid?, document.errors.full_messages.inspect
    document = Document.new(file: upload(FORM, "form.pdf", "application/pdf"))
    refute document.valid?
    assert_equal :malmal_suspicious, document.errors.details[:file].first[:error]
  end

  test "every file of a has_many_attached is checked" do
    document = Document.new(pages: [upload(GIF, "a.gif"), upload(ELF, "b.jpg"), upload(ELF, "c.png")])
    refute document.valid?
    assert_equal(%w[b.jpg c.png], document.errors.details[:pages].map { |detail| detail[:filename] })
  end

  test "a file that cannot be scanned is refused" do
    broken = Object.new
    def broken.scan(*, **) = raise(Malmal::ScanError, "down")
    Malmal::Rails.stub(:scanner_for, broken) do
      document = Document.new(file: upload(GIF, "a.gif"))
      refute document.valid?
      assert_equal :malmal_error, document.errors.details[:file].first[:error]
    end
  end

  test "unknown options are refused when the model is defined" do
    error = assert_raises(ArgumentError) do
      Class.new(ActiveRecord::Base) do
        self.table_name = "documents"
        has_one_attached :file
        validates :file, malmal: { polcy: :strict }
      end
    end
    assert_match(/polcy/, error.message)
  end
end
