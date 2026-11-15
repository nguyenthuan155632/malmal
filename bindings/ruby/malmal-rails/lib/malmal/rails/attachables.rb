# frozen_string_literal: true

module Malmal
  module Rails
    # What is being attached to a record, read back from Active Storage's
    # pending changes before anything is uploaded.
    module Attachables
      # One file being attached: its bytes come from +io+ (an upload not yet
      # stored) or from +blob+ (one already stored, as after a direct upload).
      Upload = Struct.new(:attachable, :blob, :filename, :content_type, :io, keyword_init: true) do
        def stored?
          io.nil?
        end
      end

      module_function

      # The uploads that +record+ is about to attach as +name+; none when
      # nothing new is being attached.
      def pending(record, name)
        return [] unless record.respond_to?(:attachment_changes)

        change = record.attachment_changes[name.to_s]
        pairs = case change
                when ::ActiveStorage::Attached::Changes::CreateOne
                  [[change.attachable, change.blob]]
                when ::ActiveStorage::Attached::Changes::CreateMany
                  change.attachables.zip(change.blobs)
                else
                  []
                end
        pairs.filter_map { |attachable, blob| upload(attachable, blob) }
      end

      def upload(attachable, blob)
        case attachable
        when ::ActiveStorage::Blob, ::ActiveStorage::Attachment, String
          return nil if already_attached?(blob)

          Upload.new(attachable: attachable, blob: blob, filename: blob.filename.to_s,
                     content_type: blob.content_type)
        when Hash
          options = attachable.symbolize_keys
          Upload.new(attachable: attachable, blob: blob, io: options.fetch(:io),
                     filename: options[:filename].to_s, content_type: options[:content_type])
        else
          io = attachable.respond_to?(:tempfile) ? attachable.tempfile : attachable
          filename = attachable.respond_to?(:original_filename) ? attachable.original_filename : blob.filename.to_s
          content_type = attachable.respond_to?(:content_type) ? attachable.content_type : blob.content_type
          Upload.new(attachable: attachable, blob: blob, io: io, filename: filename.to_s, content_type: content_type)
        end
      end

      # A blob the record already had is not scanned again on every save.
      def already_attached?(blob)
        blob.persisted? && blob.attachments.exists?
      end

      # The bytes of an upload, at most +limit+ of them.
      def read(upload, limit)
        return read_stored(upload.blob, limit) if upload.stored?

        io = upload.io
        io.rewind if io.respond_to?(:rewind)
        bytes = io.read(limit) || +""
        io.rewind if io.respond_to?(:rewind)
        bytes.b
      end

      def read_stored(blob, limit)
        return blob.download_chunk(0...limit).b if blob.byte_size.to_i > limit

        blob.download.b
      end
    end
  end
end
