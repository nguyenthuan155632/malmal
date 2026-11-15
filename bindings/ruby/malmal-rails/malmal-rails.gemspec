# frozen_string_literal: true

require_relative "../malmal/lib/malmal/version" unless defined?(Malmal::VERSION)

Gem::Specification.new do |spec|
  spec.name = "malmal-rails"
  spec.version = Malmal::VERSION
  spec.authors = ["nguyenthuan155632"]
  spec.summary = "Scan and rebuild Active Storage uploads with malmal"
  spec.description = <<~TEXT
    Rails integration for the malmal upload scanner: a validator for Active Storage
    attachments, scans of stored blobs (direct uploads included) recorded in their
    metadata, attachments rebuilt from what they draw, and config.malmal.
  TEXT
  spec.homepage = "https://github.com/nguyenthuan155632/malmal"
  spec.licenses = ["MIT", "Apache-2.0"]
  spec.required_ruby_version = ">= 3.2"
  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => "#{spec.homepage}/tree/main/bindings/ruby/malmal-rails",
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir["lib/**/*.rb", "lib/generators/**/*", "config/**/*.yml", "README.md", "LICENSE-MIT",
                   "LICENSE-APACHE"]
  spec.require_paths = ["lib"]

  spec.add_dependency "activestorage", ">= 7.1", "< 9"
  spec.add_dependency "malmal", "= #{Malmal::VERSION}"
  spec.add_dependency "railties", ">= 7.1", "< 9"
end
