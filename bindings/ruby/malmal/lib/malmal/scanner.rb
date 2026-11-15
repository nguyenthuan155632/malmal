# frozen_string_literal: true

require "json"

module Malmal
  # A configured scanner. One instance may be shared by every thread of the
  # process: it holds no per-scan state.
  #
  #   scanner = Malmal::Scanner.new(policy: :documents, types: %i[jpeg png pdf])
  #   report = scanner.scan(upload, filename: "a.pdf", content_type: "application/pdf")
  #   raise "rejected: #{report.codes.join(", ")}" unless report.clean?
  class Scanner
    POLICIES = %i[default strict documents].freeze
    LIMITS = %i[max_size max_decompressed max_pixels max_depth scan_timeout].freeze
    SANITIZE_OPTIONS = %i[types pdf_dpi pdf_jpeg pdf_text pdf_vector_text].freeze
    DEFAULT_MAX_MEMORY = 512 << 20

    # The handle is freed when the scanner is collected, unless #close
    # freed it first.
    class Handle < FFI::AutoPointer
      def self.release(pointer)
        Native.malmal_scanner_free(pointer)
      end
    end
    private_constant :Handle

    attr_reader :options

    # +policy+:: +:default+, +:strict+ or +:documents+ (XFA forms and
    #            attachments in PDFs do not count; what they hold does).
    # +allow+:: finding codes reported at +:info+, such as
    #           <tt>%w[pdf.xfa]</tt>; an unknown code, or a +limit.*+ one,
    #           raises ArgumentError.
    # +types+:: the accepted file types, such as <tt>%i[jpeg png pdf]</tt>;
    #           every supported type when nil.
    # +hashlist+:: a SHA-256 blocklist as text, one hex digest per line.
    # +pdf_passwords+:: passwords to try on encrypted PDFs.
    # +max_size+, +max_decompressed+, +max_pixels+, +max_depth+,
    # +scan_timeout+ (seconds):: the limits of one scan.
    # +max_memory+:: bytes one scan may hold; nil or 0 for no limit.
    # +without_hash+:: leave the SHA-256 out of reports.
    # +wait+:: seconds after which #scan stops waiting and reports
    #          +limit.time+ even if a step of the scan never ends; the scan
    #          is left running on its thread (see #overdue).
    def initialize(policy: :default, allow: [], types: nil, hashlist: nil, pdf_passwords: [],
                   max_memory: DEFAULT_MAX_MEMORY, without_hash: false, wait: nil, **limits)
      unknown = limits.keys - LIMITS
      raise ArgumentError, "unknown option #{unknown.first.inspect}" unless unknown.empty?
      raise ArgumentError, "max_memory cannot be negative" if max_memory&.negative?

      Native.load!
      @options = {
        policy: policy.to_s,
        allow: Array(allow).flat_map { |code| code.to_s.split(/[,|]/) }.map(&:strip).reject(&:empty?),
        pdf_passwords: Array(pdf_passwords).map { |password| password_json(password) },
        max_memory: max_memory || 0,
        without_hash: without_hash ? true : false
      }
      @options[:types] = Array(types).map(&:to_s) if types
      @options[:hashlist] = hashlist.to_s if hashlist
      @options[:wait] = wait if wait
      @options.merge!(limits)
      @handle = build(JSON.generate(@options))
      @mutex = Mutex.new
    end

    # Scan +data+: a String of bytes, or an IO read up to the size limit and
    # one byte past it. +filename+ and +content_type+ are what the uploader
    # claimed. Returns a Report; raises ScanError if the file was not scanned.
    def scan(data, filename: nil, content_type: nil)
      bytes = read(data)
      with_input(bytes) do |pointer|
        report = FFI::MemoryPointer.new(:pointer)
        verdict = Native.malmal_scan(handle, pointer, bytes.bytesize, claim(filename), claim(content_type), report)
        json = take_string(report.read_pointer)
        raise ScanError, "the scanner failed; the file was not scanned" if verdict == Native::ERROR || json.nil?

        Report.from_h(JSON.parse(json))
      end
    end

    # Scan +data+ and, if it is clean and of a type that can be, write it
    # anew. Returns a Sanitized whose +data+ is the file to keep in place of
    # the upload. Raises Rejected, NotRebuilt or ScanError otherwise; in
    # every case the upload is not to be kept.
    #
    # +jpeg_quality+ (1 to 100), +types+, +pdf_dpi+, +pdf_jpeg+, +pdf_text+
    # and +pdf_vector_text+ are the options of the rebuild.
    def sanitize(data, filename: nil, content_type: nil, jpeg_quality: nil, **options)
      unknown = options.keys - SANITIZE_OPTIONS
      raise ArgumentError, "unknown option #{unknown.first.inspect}" unless unknown.empty?

      options[:types] = Array(options[:types]).map(&:to_s) if options.key?(:types)
      options[:jpeg_quality] = jpeg_quality if jpeg_quality
      bytes = read(data)
      with_input(bytes) do |pointer|
        image = FFI::MemoryPointer.new(:pointer)
        length = FFI::MemoryPointer.new(:size_t)
        info = FFI::MemoryPointer.new(:pointer)
        status = Native.malmal_sanitize_json(handle, pointer, bytes.bytesize, claim(filename), claim(content_type),
                                             JSON.generate(options), image, length, info)
        rebuilt = take_bytes(image.read_pointer, length.read(:size_t))
        json = take_string(info.read_pointer)
        sanitized(status, rebuilt, json ? JSON.parse(json) : {})
      end
    end

    # Scans that +wait+ stopped waiting for and that are still running.
    # Above 0, restart the process when it can be.
    def overdue
      Native.malmal_scanner_overdue(handle)
    end

    # The version of the loaded libmalmal_ffi.
    def library_version
      Native.version
    end

    # Free the scanner now rather than when it is collected.
    def close
      @mutex.synchronize do
        @handle&.free
        @handle = nil
      end
    end

    def closed?
      @handle.nil?
    end

    def inspect
      "#<Malmal::Scanner policy=#{@options[:policy]}#{" closed" if closed?}>"
    end

    private

    def build(json)
      error = FFI::MemoryPointer.new(:pointer)
      pointer = Native.malmal_scanner_new_json(json, error)
      if pointer.null?
        message = take_string(error.read_pointer) || "the scanner could not be created"
        raise ArgumentError, message
      end
      Handle.new(pointer)
    end

    def handle
      @handle or raise ScanError, "the scanner is closed"
    end

    def password_json(password)
      text = password.to_s
      return text if text.encoding != Encoding::BINARY && text.valid_encoding?

      utf8 = text.dup.force_encoding(Encoding::UTF_8)
      utf8.valid_encoding? ? utf8 : text.bytes
    end

    def read(data)
      return data.b if data.is_a?(String)

      if data.respond_to?(:read)
        data.rewind if data.respond_to?(:rewind)
        limit = (@options[:max_size] || (64 << 20)) + 1
        bytes = data.read(limit) || +""
        data.rewind if data.respond_to?(:rewind)
        return bytes.b
      end
      raise TypeError, "scan takes a String or an IO, not #{data.class}"
    end

    # A NUL would end the C string early; it is dropped, as the C library
    # would drop what follows it.
    def claim(text)
      text&.to_s&.delete("\0")
    end

    def with_input(bytes)
      pointer = FFI::MemoryPointer.new(:uint8, [bytes.bytesize, 1].max)
      pointer.put_bytes(0, bytes)
      yield pointer
    ensure
      pointer&.free
    end

    def take_string(pointer)
      return nil if pointer.null?

      pointer.read_string.force_encoding(Encoding::UTF_8)
    ensure
      Native.malmal_string_free(pointer) unless pointer.null?
    end

    def take_bytes(pointer, length)
      return nil if pointer.null?

      pointer.read_bytes(length)
    ensure
      Native.malmal_bytes_free(pointer, length) unless pointer.null?
    end

    def sanitized(status, rebuilt, fields)
      case status
      when Native::CLEAN
        raise ScanError, "the scanner failed; there is no rebuilt file" unless rebuilt

        image = fields.fetch("image")
        Sanitized.new(data: rebuilt, file_type: image.fetch("file_type"), width: image.fetch("width", 0),
                      height: image.fetch("height", 0), frames: image.fetch("frames", 1),
                      report: Report.from_h(fields.fetch("report")))
      when Native::NOT_REBUILT
        raise NotRebuilt, fields.fetch("error", "the file was not rebuilt")
      when Native::SUSPICIOUS, Native::MALICIOUS
        raise Rejected, Report.from_h(fields.fetch("report"))
      else
        raise ArgumentError, fields["error"] if fields["error"]

        raise ScanError, "the scanner failed; the file was not scanned"
      end
    end
  end
end
