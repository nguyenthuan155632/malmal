# frozen_string_literal: true

require_relative "lib/malmal/version"

Gem::Specification.new do |spec|
  spec.name = "malmal"
  spec.version = Malmal::VERSION
  spec.authors = ["nguyenthuan155632"]
  spec.summary = "Upload scanner for images, SVG, PDF and PostScript files"
  spec.description = <<~TEXT
    Checks uploaded files before your application processes them: whether the content is
    what the name and Content-Type claim, whether it carries active content (scripts,
    actions, embedded files, shell commands), and whether it is well formed. It can also
    rebuild an image, SVG or PDF from what it draws. A file that cannot be analyzed
    completely is never reported clean.
  TEXT
  spec.homepage = "https://github.com/nguyenthuan155632/malmal"
  spec.licenses = ["MIT", "Apache-2.0"]
  spec.required_ruby_version = ">= 3.2"
  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => "#{spec.homepage}/tree/main/bindings/ruby/malmal",
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir["lib/**/*.rb", "sig/**/*.rbs", "README.md", "LICENSE-MIT", "LICENSE-APACHE"]
  spec.require_paths = ["lib"]

  # A platform gem carries the library built for it (see build_gem.sh); the
  # plain gem carries none and loads the one at MALMAL_LIBRARY.
  if (platform = ENV.fetch("MALMAL_GEM_PLATFORM", nil))
    spec.platform = Gem::Platform.new(platform)
    spec.files += Dir["lib/malmal/libmalmal_ffi.{so,dylib}"]
  end

  spec.add_dependency "ffi", "~> 1.16"
end
