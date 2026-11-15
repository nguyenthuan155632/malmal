# frozen_string_literal: true

require "malmal"
require "active_support"
require "active_support/core_ext/module/attribute_accessors"
require "active_support/ordered_options"

module Malmal
  # Rails integration: one scanner for the application, built from
  # +config.malmal+, an Active Storage validator, scans of stored blobs, and
  # attachments rebuilt from what they draw.
  module Rails
    # The options +config.malmal+ starts with.
    DEFAULTS = {
      policy: :default,
      allow: [],
      types: nil,
      limits: {},
      max_memory: Malmal::Scanner::DEFAULT_MAX_MEMORY,
      wait: nil,
      pdf_passwords: [],
      client_url: nil,
      client_token: nil,
      scan_blobs: true,
      purge_unclean: false,
      log_filenames: false
    }.freeze

    SCANNER_OPTIONS = %i[policy allow types max_memory wait pdf_passwords].freeze

    LOCK = Mutex.new
    private_constant :LOCK

    class << self
      # The options in use; in an application, +config.malmal+.
      def config
        @config ||= ActiveSupport::OrderedOptions.new.merge!(DEFAULTS.deep_dup)
      end

      attr_writer :config

      # What scans for the application: a Malmal::Scanner, or a
      # Malmal::Client when +client_url+ is set. Built on first use, then
      # shared by every thread.
      def scanner
        @scanner || LOCK.synchronize { @scanner ||= build(config) }
      end

      # A scanner with +overrides+ of the scanning options of +config+, for a
      # validator that asks for its own policy or types; built once for each
      # set of overrides.
      def scanner_for(overrides)
        overrides = overrides.slice(*SCANNER_OPTIONS)
        return scanner if overrides.empty?

        if config.client_url
          raise ArgumentError, "#{overrides.keys.join(", ")} cannot be set per validator when scanning with malmald; " \
                               "start the daemon with them instead"
        end
        LOCK.synchronize do
          @scanners ||= {}
          @scanners[overrides] ||= build(config.merge(overrides))
        end
      end

      # Forget the scanners built so far, so that the next scan builds them
      # from the configuration again.
      def reset!
        LOCK.synchronize do
          @scanner = nil
          @scanners = nil
        end
      end

      # Scan +data+ (a String or an IO) with +scanner+, and tell
      # ActiveSupport::Notifications (+scan.malmal+) and the log about it.
      def scan(data, filename: nil, content_type: nil, scanner: self.scanner)
        payload = { filename: filename, content_type: content_type }
        report = ActiveSupport::Notifications.instrument("scan.malmal", payload) do
          payload[:report] = scanner.scan(data, filename: filename, content_type: content_type)
        end
        log(report, filename) unless report.clean?
        report
      end

      # Rebuild +data+ with +scanner+; +sanitize.malmal+ is instrumented.
      def sanitize(data, filename: nil, content_type: nil, scanner: self.scanner, **options)
        payload = { filename: filename, content_type: content_type }
        ActiveSupport::Notifications.instrument("sanitize.malmal", payload) do
          payload[:sanitized] = scanner.sanitize(data, filename: filename, content_type: content_type, **options)
        end
      end

      # The size limit of a scan and one byte past it: what is read of an
      # upload, so that an oversized one is reported as such.
      def read_limit
        limits = (config.limits || {}).to_h.symbolize_keys
        (limits[:max_size] || (64 << 20)) + 1
      end

      def logger
        defined?(::Rails.logger) && ::Rails.logger ? ::Rails.logger : nil
      end

      private

      def build(options)
        return Malmal::Client.new(options[:client_url], token: options[:client_token]) if options[:client_url]

        Malmal::Scanner.new(
          policy: options[:policy] || :default,
          allow: options[:allow] || [],
          types: options[:types],
          pdf_passwords: options[:pdf_passwords] || [],
          max_memory: options[:max_memory],
          wait: options[:wait],
          **(options[:limits] || {}).to_h.symbolize_keys
        )
      end

      def log(report, filename)
        return unless logger

        name = config.log_filenames && filename ? " #{filename.inspect}" : ""
        logger.warn("[malmal] #{report.verdict} upload#{name}: #{report.codes.join(", ")}")
      end
    end
  end
end

require_relative "rails/version"
require_relative "rails/attachables"
require_relative "rails/validator"
require_relative "rails/blob_scan"
require_relative "rails/sanitizes_attachment"
require_relative "rails/railtie" if defined?(Rails::Railtie)
