# frozen_string_literal: true

module Malmal
  module Rails
    # Scans a stored blob when Active Storage analyzes it, which it does in a
    # job after every upload, direct ones included, and records the result
    # in its metadata:
    #
    #   blob.metadata["malmal"]  # => {"verdict" => "malicious", "codes" => ["type.executable"]}
    #   blob.malmal_clean?       # => false
    #
    # With +config.malmal.purge_unclean+, a blob that is not clean is purged,
    # with its attachments. Validations do not see direct uploads until the
    # record is saved; this is what catches the ones that are never attached.
    module BlobScan
      module_function

      def call(blob)
        return unless Malmal::Rails.config.scan_blobs

        report = Malmal::Rails.scan(read(blob), filename: blob.filename.to_s, content_type: blob.content_type)
        record(blob, report.verdict.to_s, report.codes)
        purge(blob) if !report.clean? && Malmal::Rails.config.purge_unclean
      rescue Malmal::ScanError, Malmal::LoadError => e
        Malmal::Rails.logger&.error("[malmal] blob #{blob.id} was not scanned: #{e.message}")
        record(blob, "error", [])
        purge(blob) if Malmal::Rails.config.purge_unclean
      end

      def read(blob)
        Attachables.read_stored(blob, Malmal::Rails.read_limit)
      end

      def record(blob, verdict, codes)
        result = { "verdict" => verdict, "codes" => codes, "version" => Malmal::VERSION }
        blob.update!(metadata: blob.metadata.merge("malmal" => result))
      end

      def purge(blob)
        Malmal::Rails.logger&.warn("[malmal] purging blob #{blob.id}, which is not clean")
        attachments = blob.attachments.to_a
        if attachments.empty?
          blob.purge
        else
          attachments.each(&:purge)
        end
      end

      # Included in ActiveStorage::Blob.
      module Blob
        # The blob is scanned even when Active Storage's own analyzer fails
        # (an analyzer that cannot load what it needs), and that
        # failure is raised afterwards.
        def analyze
          begin
            super
          rescue StandardError
            Malmal::Rails::BlobScan.call(self)
            raise
          end
          Malmal::Rails::BlobScan.call(self)
        end

        # Whether the last scan of this blob came back clean; nil if it has
        # not been scanned.
        def malmal_clean?
          verdict = metadata.dig("malmal", "verdict")
          verdict && verdict == "clean"
        end
      end
    end
  end
end
