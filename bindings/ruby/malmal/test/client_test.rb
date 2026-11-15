# frozen_string_literal: true

require "test_helper"
require "socket"
require "tmpdir"
require "fileutils"

# Runs against a real malmald when MALMALD names its binary.
class ClientTest < Minitest::Test
  include Samples

  TOKEN = "a-token-of-thirty-two-characters"

  def setup
    binary = ENV.fetch("MALMALD", nil)
    skip "MALMALD is not set" unless binary && File.executable?(binary)

    @dir = Dir.mktmpdir
    token_file = File.join(@dir, "token")
    File.write(token_file, "#{TOKEN}\n")
    reader, writer = IO.pipe
    @pid = Process.spawn(binary, "--http", "127.0.0.1:0", "--token-file", token_file, "--no-sandbox",
                         err: writer, out: File::NULL)
    writer.close
    banner = reader.gets.to_s
    address = banner[/listening on (\S+)/, 1] or flunk "unexpected banner #{banner.inspect}"
    @url = "http://#{address}"
  end

  def teardown
    return unless @pid

    Process.kill("TERM", @pid)
    Process.wait(@pid)
    FileUtils.remove_entry(@dir)
  end

  def client(token: TOKEN)
    Malmal::Client.new(@url, token: token)
  end

  def test_scan
    assert_predicate client.scan(GIF, filename: "a b.gif", content_type: "image/gif"), :clean?
    report = client.scan(ELF, filename: "photo.jpg")
    assert_predicate report, :malicious?
    assert_includes report.codes, "type.executable"
    assert_predicate client, :healthy?
  end

  def test_token_is_required
    error = assert_raises(Malmal::ScanError) { client(token: nil).scan(GIF) }
    assert_match(/401/, error.message)
    assert_predicate client(token: nil), :healthy?
  end

  def test_sanitize
    sanitized = client.sanitize(png_with_comment, filename: "a.png")
    assert_equal :png, sanitized.file_type
    refute_includes sanitized.data, "holiday"
    assert_raises(Malmal::Rejected) { client.sanitize(ELF, filename: "photo.jpg") }
    assert_equal :png, client.sanitize(png_with_comment, filename: "a.png", types: %i[png jpeg]).file_type
    assert_raises(Malmal::NotRebuilt) { client.sanitize(png_with_comment, filename: "a.png", types: [:jpeg]) }
    assert_raises(ArgumentError) { client.sanitize(png_with_comment, jpeg_quality: 80) }
  end

  def test_unreachable
    closed = Malmal::Client.new("http://127.0.0.1:1")
    assert_raises(Malmal::ScanError) { closed.scan(GIF) }
    refute_predicate closed, :healthy?
  end
end
