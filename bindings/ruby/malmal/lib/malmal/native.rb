# frozen_string_literal: true

require "ffi"

module Malmal
  # The functions of libmalmal_ffi, as declared in malmal.h. Each that scans
  # releases the GVL, so other Ruby threads run while a file is scanned.
  module Native
    extend FFI::Library

    CLEAN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2
    ERROR = 3
    NOT_REBUILT = 4

    NAMES = %w[libmalmal_ffi.so libmalmal_ffi.dylib malmal_ffi.dll].freeze
    LOCK = Mutex.new
    private_constant :LOCK

    class << self
      # Where the library was loaded from.
      attr_reader :path

      # The library this gem carries, else the one at MALMAL_LIBRARY, else
      # whatever the system loader finds.
      def candidates
        bundled = NAMES.map { |name| File.join(__dir__, name) }.select { |file| File.file?(file) }
        [ENV.fetch("MALMAL_LIBRARY", nil), *bundled, "malmal_ffi"].compact.reject(&:empty?)
      end

      # The version of the loaded library.
      def version
        malmal_version.dup.force_encoding(Encoding::UTF_8)
      end

      # Load the library once, whichever thread asks first.
      def load!
        return if @loaded

        LOCK.synchronize { load_once! unless @loaded }
      end

      private

      def load_once!
        errors = []
        candidates.each do |candidate|
          ffi_lib(candidate)
          @path = candidate
          break
        rescue ::LoadError => e
          errors << e.message
        end
        unless @path
          raise Malmal::LoadError,
                "libmalmal_ffi was not found (#{errors.join("; ")}). This gem has no library for " \
                "#{RUBY_PLATFORM}; build one with `cargo build --release -p malmal-ffi` and set " \
                "MALMAL_LIBRARY to its path."
        end
        attach!
        check_version!
        @loaded = true
      end

      def attach!
        attach_function :malmal_version, [], :string
        attach_function :malmal_scanner_new_json, %i[string pointer], :pointer
        attach_function :malmal_scanner_overdue, [:pointer], :uint64
        attach_function :malmal_scanner_free, [:pointer], :void
        attach_function :malmal_scan, %i[pointer pointer size_t string string pointer], :int, blocking: true
        attach_function :malmal_sanitize_json,
                        %i[pointer pointer size_t string string string pointer pointer pointer], :int,
                        blocking: true
        attach_function :malmal_string_free, [:pointer], :void
        attach_function :malmal_bytes_free, %i[pointer size_t], :void
      rescue FFI::NotFoundError => e
        raise Malmal::LoadError, "#{@path} is older than this gem (#{e.message}); it needs #{Malmal::VERSION}"
      end

      # The library this gem carries has to be its own version; one given
      # with MALMAL_LIBRARY only has to have the functions.
      def check_version!
        return if version == Malmal::VERSION
        return if ENV["MALMAL_LIBRARY"].to_s == @path

        raise Malmal::LoadError, "#{@path} is version #{version}, and this gem is #{Malmal::VERSION}"
      end
    end
  end
end
