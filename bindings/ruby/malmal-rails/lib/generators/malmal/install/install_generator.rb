# frozen_string_literal: true

require "rails/generators/base"

module Malmal
  module Generators
    # bin/rails generate malmal:install
    class InstallGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)
      desc "Writes config/initializers/malmal.rb, where the scanner is configured."

      def copy_initializer
        template "malmal.rb", "config/initializers/malmal.rb"
      end
    end
  end
end
