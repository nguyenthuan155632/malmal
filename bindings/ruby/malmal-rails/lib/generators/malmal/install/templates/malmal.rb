# frozen_string_literal: true

# The scanner the application uses for every upload. See
# https://github.com/nguyenthuan155632/malmal/tree/main/bindings/ruby/malmal-rails
Rails.application.configure do
  # :default, :strict, or :documents (XFA forms and attachments in PDFs do not
  # count against a file; what they contain still does).
  config.malmal.policy = :default

  # Finding codes that do not count against a file (docs/findings.md).
  # config.malmal.allow = %w[pdf.xfa]

  # The file types accepted; every supported type when nil.
  # config.malmal.types = %i[jpeg png gif webp pdf]

  # The limits of one scan.
  # config.malmal.limits = { max_size: 20.megabytes, scan_timeout: 10 }

  # Answer within this many seconds even if a step of a scan never ends.
  # config.malmal.wait = 30

  # Scan with a running malmald instead of in this process.
  # config.malmal.client_url = "http://127.0.0.1:8080"
  # config.malmal.client_token = ENV["MALMAL_TOKEN"]

  # Scan every stored blob when Active Storage analyzes it, and record the
  # result in blob.metadata["malmal"].
  config.malmal.scan_blobs = true

  # Purge a stored blob that is not clean, with its attachments.
  config.malmal.purge_unclean = false

  # Log the names of files that are not clean.
  config.malmal.log_filenames = false
end
