# frozen_string_literal: true

module Malmal
  # The base of every error the gem raises.
  class Error < StandardError; end

  # The file was not scanned. Treat it as not accepted.
  class ScanError < Error; end

  # There is no rebuilt file, and the original is not to be kept in its place.
  class SanitizeError < Error; end

  # The scan of the upload, or of the file made from it, did not come back
  # clean; +report+ is the one that was not.
  class Rejected < SanitizeError
    attr_reader :report

    def initialize(report)
      @report = report
      super("file is not clean: #{report.codes.join(", ")}")
    end
  end

  # The file is clean but is not of a type that can be rebuilt, is too large,
  # or does not decode.
  class NotRebuilt < SanitizeError; end

  # libmalmal_ffi could not be found or is not the version this gem needs.
  class LoadError < Error; end
end
