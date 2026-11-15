# frozen_string_literal: true

require "active_model"

module Malmal
  module Rails
    # Validates what is being attached to an Active Storage attachment:
    #
    #   class Document < ApplicationRecord
    #     has_one_attached :file
    #     validates :file, malmal: true
    #     # or: validates :file, malmal: { policy: :documents, types: %i[pdf png jpeg] }
    #   end
    #
    # Each new upload is scanned before it is stored, with the file name and
    # Content-Type the client gave; a blob already stored (a direct upload,
    # a signed id) is read back and scanned. Attachments the record already
    # had are not scanned again. A file that is not clean adds an error to
    # the attribute: +:malmal_suspicious+, +:malmal_malicious+, or
    # +:malmal_error+ when it could not be scanned, with the finding codes in
    # +errors.details+ (+codes:+) and the file name (+filename:+).
    #
    # Options: +policy+, +allow+, +types+, +max_memory+, +wait+ and
    # +pdf_passwords+ build a scanner of their own from +config.malmal+ with
    # those changes. +message+ replaces the error message, as with any
    # validator.
    class Validator < ::ActiveModel::EachValidator
      def check_validity!
        unknown = options.keys - SCANNER_OPTIONS - %i[message if unless on allow_nil allow_blank strict]
        raise ArgumentError, "unknown malmal option #{unknown.first.inspect}" unless unknown.empty?
      end

      def validate_each(record, attribute, _value)
        Attachables.pending(record, attribute).each do |upload|
          check(record, attribute, upload)
        end
      end

      private

      def check(record, attribute, upload)
        data = Attachables.read(upload, Malmal::Rails.read_limit)
        report = Malmal::Rails.scan(data, filename: upload.filename, content_type: upload.content_type,
                                          scanner: Malmal::Rails.scanner_for(options))
        return if report.clean?

        add(record, attribute, :"malmal_#{report.verdict}", upload, report.codes)
      rescue Malmal::ScanError, Malmal::LoadError => e
        Malmal::Rails.logger&.error("[malmal] #{upload.filename.inspect} was not scanned: #{e.message}")
        add(record, attribute, :malmal_error, upload, [])
      end

      def add(record, attribute, error, upload, codes)
        details = { filename: upload.filename, codes: codes, count: codes.size }
        details[:message] = options[:message] if options[:message]
        record.errors.add(attribute, error, **details)
      end
    end
  end
end

# `validates :file, malmal: true` looks the validator up by this name.
MalmalValidator = Malmal::Rails::Validator unless defined?(MalmalValidator)
