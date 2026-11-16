# frozen_string_literal: true

require "active_support/concern"
require "stringio"

module Malmal
  module Rails
    # Replaces what is attached with a file written anew from what it draws,
    # before the record is validated, so that nothing else from the upload
    # is stored:
    #
    #   class User < ApplicationRecord
    #     has_one_attached :avatar
    #     sanitizes_attachment :avatar, types: %i[jpeg png webp]
    #   end
    #
    # The new file keeps the name of the upload, with the extension of its
    # type, which is not always the type of the upload (a BMP becomes a PNG).
    # An upload that is not clean adds +:malmal_suspicious+ or
    # +:malmal_malicious+ to the attribute; one that cannot be rebuilt adds
    # +:malmal_not_rebuilt+, or is kept as it was with
    # <tt>on_not_rebuilt: :keep</tt> (pair that with the validator). Other
    # options are those of Malmal::Scanner#sanitize: +types+, +jpeg_quality+,
    # +keep_cmyk+, +keep_profile+, +tone_map+, +pdf_dpi+, +pdf_jpeg+, +pdf_text+, +pdf_vector_text+.
    module SanitizesAttachment
      extend ActiveSupport::Concern

      ON_NOT_REBUILT = %i[reject keep].freeze

      class_methods do
        def sanitizes_attachment(*names, on_not_rebuilt: :reject, **options)
          unless ON_NOT_REBUILT.include?(on_not_rebuilt)
            raise ArgumentError, "on_not_rebuilt is :reject or :keep, not #{on_not_rebuilt.inspect}"
          end

          unknown = options.keys - Malmal::Scanner::SANITIZE_OPTIONS - [:jpeg_quality]
          raise ArgumentError, "unknown option #{unknown.first.inspect}" unless unknown.empty?

          names.each do |name|
            before_validation { malmal_sanitize_attachment(name, on_not_rebuilt, options) }
            validate { malmal_sanitize_errors(name) }
          end
        end
      end

      private

      def malmal_sanitize_attachment(name, on_not_rebuilt, options)
        uploads = Attachables.pending(self, name)
        return if uploads.empty?

        failures = (@malmal_sanitize_failures ||= {})[name.to_s] = []
        rebuilt = uploads.map do |upload|
          malmal_rebuild(upload, on_not_rebuilt, options, failures)
        end
        return unless failures.empty?

        many = attachment_changes[name.to_s].is_a?(::ActiveStorage::Attached::Changes::CreateMany)
        public_send(:"#{name}=", many ? keep_existing(name, rebuilt) : rebuilt.first)
      end

      def malmal_rebuild(upload, on_not_rebuilt, options, failures)
        data = Attachables.read(upload, Malmal::Rails.read_limit)
        sanitized = Malmal::Rails.sanitize(data, filename: upload.filename, content_type: upload.content_type,
                                                 **options)
        { io: StringIO.new(sanitized.data), filename: rebuilt_filename(upload.filename, sanitized),
          content_type: sanitized.content_type }
      rescue Malmal::Rejected => e
        failures << [:"malmal_#{e.report.verdict}", upload, e.report.codes]
        nil
      rescue Malmal::NotRebuilt
        failures << [:malmal_not_rebuilt, upload, []] if on_not_rebuilt == :reject
        upload.attachable
      rescue Malmal::ScanError, Malmal::LoadError => e
        Malmal::Rails.logger&.error("[malmal] #{upload.filename.inspect} was not rebuilt: #{e.message}")
        failures << [:malmal_error, upload, []]
        nil
      end

      # A has_many_attached assignment replaces every attachment; the ones
      # the record had are given back as they were.
      def keep_existing(name, rebuilt)
        change = attachment_changes[name.to_s]
        pending = Attachables.pending(self, name).map(&:attachable)
        queue = rebuilt.dup
        change.attachables.map { |attachable| pending.include?(attachable) ? queue.shift : attachable }
      end

      def rebuilt_filename(filename, sanitized)
        base = File.basename(filename.to_s, ".*")
        base = "file" if base.empty?
        "#{base}#{sanitized.extension}"
      end

      def malmal_sanitize_errors(name)
        Array(@malmal_sanitize_failures&.delete(name.to_s)).each do |error, upload, codes|
          errors.add(name, error, filename: upload.filename, codes: codes, count: codes.size)
        end
      end
    end
  end
end
