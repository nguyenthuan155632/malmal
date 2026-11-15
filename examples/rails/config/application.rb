# frozen_string_literal: true

require_relative "boot"
require "rails"
require "active_record/railtie"
require "active_storage/engine"
require "active_job/railtie"
require "action_controller/railtie"
require "action_view/railtie"

Bundler.require(*Rails.groups)

module UploadDemo
  # An upload form, one attachment checked by the validator and one rebuilt
  # from what it draws.
  class Application < Rails::Application
    config.load_defaults 8.1
    config.eager_load = false
    config.active_storage.service = :local
    # Scans of stored blobs run in Active Storage's analyze job.
    config.active_job.queue_adapter = :async
    config.logger = ActiveSupport::Logger.new($stdout)
    config.hosts.clear
  end
end
