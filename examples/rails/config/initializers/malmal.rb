# frozen_string_literal: true

Rails.application.configure do
  # PDFs with forms and attachments are accepted; what they contain is not.
  config.malmal.policy = :documents
  config.malmal.types = %i[pdf jpeg png gif webp]
  config.malmal.limits = { max_size: 20.megabytes }
  config.malmal.wait = 30

  # With malmald running beside the app (see compose.yaml), scan there. The
  # scanning options above are then the daemon's flags, not these.
  if ENV["MALMAL_URL"].present?
    config.malmal.client_url = ENV["MALMAL_URL"]
    token_file = ENV.fetch("MALMAL_TOKEN_FILE", nil)
    config.malmal.client_token = ENV["MALMAL_TOKEN"] || (token_file && File.readlines(token_file).first&.strip)
  end

  # Record a scan of every stored blob in its metadata, and purge the ones
  # that are not clean: direct uploads skip validation until they are
  # attached.
  config.malmal.scan_blobs = true
  config.malmal.purge_unclean = true
end
