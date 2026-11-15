# frozen_string_literal: true

module Malmal
  # Severities from least to most serious.
  SEVERITIES = %i[info low medium high critical].freeze

  # One thing the scanner noticed about a file. +code+ is stable (the codes
  # are listed in docs/findings.md); the wording of +message+ is not.
  Finding = Struct.new(:code, :severity, :message, :offset, keyword_init: true) do
    def self.from_h(fields)
      new(
        code: fields.fetch("code"),
        severity: fields.fetch("severity").to_sym,
        message: fields.fetch("message", ""),
        offset: fields["offset"]
      )
    end

    def to_h
      { code: code, severity: severity, message: message, offset: offset }
    end
  end

  # What a scan found. Anything but a clean verdict means the file is not to
  # be accepted.
  class Report
    attr_reader :verdict, :detected_type, :declared_types, :size, :sha256, :findings

    def self.from_h(fields)
      new(
        verdict: fields.fetch("verdict").to_sym,
        detected_type: fields.fetch("detected_type").to_sym,
        declared_types: fields.fetch("declared_types", []).map(&:to_sym),
        size: fields.fetch("size", 0),
        sha256: fields.fetch("sha256", ""),
        findings: fields.fetch("findings", []).map { |finding| Finding.from_h(finding) }
      )
    end

    def initialize(verdict:, detected_type:, declared_types: [], size: 0, sha256: "", findings: [])
      @verdict = verdict
      @detected_type = detected_type
      @declared_types = declared_types.freeze
      @size = size
      @sha256 = sha256
      @findings = findings.freeze
      freeze
    end

    def clean?
      verdict == :clean
    end

    def suspicious?
      verdict == :suspicious
    end

    def malicious?
      verdict == :malicious
    end

    # The codes of the findings that count against the file: those above
    # +info+, in the order they were found.
    def codes
      findings.reject { |finding| finding.severity == :info }.map(&:code).uniq
    end

    def to_h
      {
        verdict: verdict,
        detected_type: detected_type,
        declared_types: declared_types,
        size: size,
        sha256: sha256,
        findings: findings.map(&:to_h)
      }
    end

    def inspect
      "#<Malmal::Report #{verdict} #{detected_type} codes=#{codes.inspect}>"
    end
  end

  # A file written anew from a clean upload: an image from its pixels, an SVG
  # from what draws in it, a PDF as pictures of its pages.
  class Sanitized
    CONTENT_TYPES = {
      jpeg: "image/jpeg",
      png: "image/png",
      gif: "image/gif",
      webp: "image/webp",
      svg: "image/svg+xml",
      pdf: "application/pdf"
    }.freeze

    EXTENSIONS = { jpeg: ".jpg", png: ".png", gif: ".gif", webp: ".webp", svg: ".svg", pdf: ".pdf" }.freeze

    # +data+ is the file to keep; +file_type+ its type, which is not always
    # the type of the upload. +width+ and +height+ are 0 for an SVG or a PDF;
    # +frames+ counts the frames of an animation or the pages of a PDF.
    attr_reader :data, :file_type, :width, :height, :frames, :report

    def initialize(data:, file_type:, report:, width: 0, height: 0, frames: 1)
      @data = data
      @file_type = file_type.to_sym
      @width = width
      @height = height
      @frames = frames
      @report = report
      freeze
    end

    def content_type
      CONTENT_TYPES.fetch(file_type, "application/octet-stream")
    end

    def extension
      EXTENSIONS.fetch(file_type, "")
    end

    def inspect
      "#<Malmal::Sanitized #{file_type} #{data.bytesize} bytes>"
    end
  end
end
