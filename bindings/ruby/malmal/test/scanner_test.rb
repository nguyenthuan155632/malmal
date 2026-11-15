# frozen_string_literal: true

require "test_helper"
require "stringio"

class ScannerTest < Minitest::Test
  include Samples

  def scanner
    @scanner ||= Malmal::Scanner.new
  end

  def test_verdicts
    report = scanner.scan(GIF, filename: "a.gif", content_type: "image/gif")
    assert_predicate report, :clean?
    assert_equal :gif, report.detected_type
    assert_equal [:gif], report.declared_types
    assert_equal Digest::SHA256.hexdigest(GIF), report.sha256
    assert_equal GIF.bytesize, report.size

    report = scanner.scan(ELF, filename: "photo.jpg")
    assert_predicate report, :malicious?
    assert_includes report.codes, "type.executable"
    finding = report.findings.find { |f| f.code == "type.executable" }
    assert_includes Malmal::SEVERITIES, finding.severity

    assert_predicate scanner.scan("plain text"), :suspicious?
    assert_predicate scanner.scan(""), :suspicious?
    assert_equal "clean", JSON.generate(report.to_h.merge(verdict: :clean))[/"verdict":"(\w+)"/, 1]
  end

  def test_io_is_read_and_rewound
    io = StringIO.new(GIF)
    assert_predicate scanner.scan(io, filename: "a.gif"), :clean?
    assert_equal 0, io.pos
    File.open(File.join(CORPUS, "clean/square.svg"), "rb") do |file|
      assert_predicate scanner.scan(file, filename: "square.svg"), :clean?
    end
    assert_raises(TypeError) { scanner.scan(42) }
  end

  def test_policies_and_allowed_codes
    assert_predicate scanner.scan(FORM, filename: "a.pdf"), :suspicious?
    assert_predicate Malmal::Scanner.new(policy: :documents).scan(FORM, filename: "a.pdf"), :clean?
    assert_predicate Malmal::Scanner.new(policy: :strict, allow: "pdf.xfa").scan(FORM, filename: "a.pdf"), :clean?
    report = Malmal::Scanner.new(allow: %w[pdf.xfa]).scan(FORM, filename: "a.pdf")
    assert_equal :info, report.findings.find { |f| f.code == "pdf.xfa" }.severity
    assert_empty report.codes

    error = assert_raises(ArgumentError) { Malmal::Scanner.new(allow: %w[pdf.embeddedfile]) }
    assert_match(/unknown finding code/, error.message)
    assert_raises(ArgumentError) { Malmal::Scanner.new(allow: %w[limit.time]) }
    assert_raises(ArgumentError) { Malmal::Scanner.new(policy: :lenient) }
    assert_raises(ArgumentError) { Malmal::Scanner.new(max_sise: 1) }
    assert_raises(ArgumentError) { Malmal::Scanner.new(max_memory: -1) }
  end

  def test_types_limits_and_hashes
    images = Malmal::Scanner.new(types: %i[png], without_hash: true)
    report = images.scan(GIF)
    assert_includes report.codes, "type.not_allowed"
    assert_equal "", report.sha256

    small = Malmal::Scanner.new(max_size: 8, wait: 60)
    assert_includes small.scan(GIF).codes, "limit.size"
    assert_equal 0, small.overdue

    blocked = Malmal::Scanner.new(hashlist: "#{Digest::SHA256.hexdigest(GIF)}\n")
    assert_predicate blocked.scan(GIF), :malicious?
    assert_raises(ArgumentError) { Malmal::Scanner.new(hashlist: "not a digest") }
  end

  def test_pdf_passwords
    pdf = corpus("malicious/password-javascript.pdf")
    severity = ->(s) { s.scan(pdf).findings.find { |f| f.code == "pdf.encrypted" }.severity }
    assert_equal :medium, severity.call(scanner)
    assert_equal :info, severity.call(Malmal::Scanner.new(pdf_passwords: ["wrong", "secret".b, "\xE9t\xE9".b]))
  end

  def test_sanitize
    sanitized = scanner.sanitize(png_with_comment, filename: "a.png")
    assert_equal :png, sanitized.file_type
    assert_equal "image/png", sanitized.content_type
    assert_equal ".png", sanitized.extension
    assert_equal [1, 1, 1], [sanitized.width, sanitized.height, sanitized.frames]
    assert sanitized.data.start_with?("\x89PNG".b)
    refute_includes sanitized.data, "holiday"
    assert_predicate sanitized.report, :clean?

    svg = scanner.sanitize(corpus("clean/square.svg"), types: %i[svg])
    assert_equal "image/svg+xml", svg.content_type

    rejected = assert_raises(Malmal::Rejected) { scanner.sanitize(ELF) }
    assert_includes rejected.report.codes, "type.executable"
    assert_raises(Malmal::Rejected) { scanner.sanitize(corpus("clean/pixels-spell-pdf.png")) }
    assert_raises(Malmal::NotRebuilt) { scanner.sanitize(png_with_comment, types: %i[jpeg]) }
    assert_raises(ArgumentError) { scanner.sanitize(png_with_comment, pdf_dpi: 5) }
    assert_raises(ArgumentError) { scanner.sanitize(png_with_comment, dpi: 100) }
  end

  def test_threads_share_one_scanner
    threads = Array.new(8) { Thread.new { Array.new(20) { scanner.scan(GIF).clean? } } }
    assert threads.flat_map(&:value).all?
  end

  def test_close
    closing = Malmal::Scanner.new
    closing.close
    closing.close
    assert_predicate closing, :closed?
    assert_raises(Malmal::ScanError) { closing.scan(GIF) }
  end

  # A picture slow enough to rebuild that another thread can act meanwhile,
  # even on a fast machine: 2000 by 2000 pixels of noise.
  def slow_png
    chunk = ->(kind, body) { [body.bytesize].pack("N") + kind + body + [Zlib.crc32(kind + body)].pack("N") }
    random = Random.new(1)
    rows = Array.new(2000) { "\0".b + random.bytes(6000) }.join
    "\x89PNG\r\n\x1a\n".b + chunk.call("IHDR", [2000, 2000, 8, 2, 0, 0, 0].pack("NNCCCCC")) +
      chunk.call("IDAT", Zlib::Deflate.deflate(rows, 1)) + chunk.call("IEND", "")
  end

  def test_close_waits_for_the_scans_running
    image = slow_png
    closing = Malmal::Scanner.new
    running = Thread.new { closing.sanitize(image) }
    sleep 0.01
    closing.close
    assert_predicate closing, :closed?
    assert_equal :png, running.value.file_type
    assert_raises(Malmal::ScanError) { closing.scan(GIF) }
  end

  def test_an_interrupt_waits_for_the_call
    image = slow_png
    running = Thread.new { scanner.sanitize(image) }
    sleep 0.01
    # An interrupt sent to a thread that has already returned is lost.
    assert running.alive?, "the rebuild finished before it could be interrupted"
    running.raise(Interrupt)
    assert_raises(Interrupt) { running.join }
    assert_predicate scanner.scan(GIF), :clean?
  end

  def test_library
    assert_equal Malmal::VERSION, scanner.library_version
    assert Malmal::Native.path
  end
end
