# frozen_string_literal: true

require "rails/railtie"

module Malmal
  module Rails
    # Sets up +config.malmal+, the validator, the scans of stored blobs and
    # +sanitizes_attachment+.
    class Railtie < ::Rails::Railtie
      config.malmal = Malmal::Rails.config

      initializer "malmal.config" do |app|
        Malmal::Rails.config = app.config.malmal
        Malmal::Rails.reset!
      end

      initializer "malmal.i18n" do
        ActiveSupport.on_load(:i18n) do
          I18n.load_path << File.expand_path("../../../config/locales/en.yml", __dir__)
        end
      end

      initializer "malmal.active_record" do
        ActiveSupport.on_load(:active_record) do
          include Malmal::Rails::SanitizesAttachment
        end
      end

      initializer "malmal.active_storage" do
        ActiveSupport.on_load(:active_storage_blob) do
          prepend Malmal::Rails::BlobScan::Blob
        end
      end

      generators do
        require_relative "../../generators/malmal/install/install_generator"
      end
    end
  end
end
