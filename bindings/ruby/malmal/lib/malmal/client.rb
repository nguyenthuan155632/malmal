# frozen_string_literal: true

require "json"
require "net/http"
require "openssl"
require "uri"

module Malmal
  # The scanner of a running malmald, over its HTTP endpoint. It answers as
  # Scanner does, and is for deployments that want what only the daemon
  # gives: the sandbox, and --hard-timeout ending a scan that does not.
  #
  #   client = Malmal::Client.new("http://127.0.0.1:8080", token: ENV["MALMAL_TOKEN"])
  #   client.scan(upload, filename: "a.png").clean?
  class Client
    attr_reader :url

    # +url+ is the daemon's base URL; +token+ the one it was started with
    # (--token-file), if any. +open_timeout+ and +read_timeout+ are seconds;
    # the read timeout has to cover the longest scan.
    def initialize(url, token: nil, open_timeout: 5, read_timeout: 120)
      @url = URI(url.to_s.chomp("/"))
      @token = token
      @open_timeout = open_timeout
      @read_timeout = read_timeout
    end

    # As Scanner#scan. Anything but an answer with a report raises ScanError.
    def scan(data, filename: nil, content_type: nil)
      response = post("/scan", data, filename, content_type)
      body = parse(response)
      unless response.code == "200" && body["ok"] && body["report"]
        raise ScanError, "malmald did not scan the file: #{response.code} #{body["error"]}".strip
      end

      Report.from_h(body["report"])
    end

    # As Scanner#sanitize, with the daemon's own options of the rebuild
    # (the --jpeg-quality and --pdf-* flags it was started with). +types+ is
    # checked here, against the type of the rebuilt file: one of another type
    # raises NotRebuilt. Any other option raises ArgumentError.
    def sanitize(data, filename: nil, content_type: nil, types: nil, **options)
      unless options.empty?
        raise ArgumentError, "#{options.keys.join(", ")} cannot be sent to malmald; start the daemon with them instead"
      end

      response = post("/sanitize", data, filename, content_type)
      case response.code
      when "200"
        file_type = Sanitized::CONTENT_TYPES.key(response["Content-Type"].to_s.split(";").first) || :unknown
        if types && !Array(types).map(&:to_sym).include?(file_type)
          raise NotRebuilt, "a #{file_type} file is not among the types to rebuild"
        end

        # The daemon does not send the report of a file it rebuilt; the
        # rebuilt file was clean, or it would not have been sent.
        report = Report.new(verdict: :clean, detected_type: file_type)
        Sanitized.new(data: response.body.b, file_type: file_type, report: report)
      when "422"
        body = parse(response)
        raise Rejected, Report.from_h(body["report"]) if body["report"]

        raise NotRebuilt, body["error"].to_s
      when "415", "501"
        raise NotRebuilt, parse(response)["error"].to_s
      else
        raise ScanError, "malmald did not rebuild the file: #{response.code} #{parse(response)["error"]}".strip
      end
    end

    # Whether the daemon answers GET /healthz.
    def healthy?
      request(Net::HTTP::Get.new(path("/healthz"))).code == "200"
    rescue StandardError
      false
    end

    private

    def path(name)
      "#{@url.path}#{name}"
    end

    def post(name, data, filename, content_type)
      bytes = data.respond_to?(:read) ? data.read.to_s : data.to_s
      data.rewind if data.respond_to?(:rewind)
      request = Net::HTTP::Post.new(path(name))
      request["Content-Type"] = content_type.to_s.empty? ? "application/octet-stream" : content_type.to_s
      request["X-Filename"] = URI.encode_www_form_component(filename.to_s).gsub("+", "%20") if filename
      request.body = bytes.b
      request(request)
    end

    def request(request)
      request["Authorization"] = "Bearer #{@token}" if @token
      Net::HTTP.start(@url.host, @url.port, use_ssl: @url.scheme == "https",
                                            open_timeout: @open_timeout, read_timeout: @read_timeout) do |http|
        http.request(request)
      end
    rescue SystemCallError, IOError, Timeout::Error, OpenSSL::SSL::SSLError => e
      raise ScanError, "malmald could not be reached: #{e.message}"
    end

    def parse(response)
      JSON.parse(response.body.to_s)
    rescue JSON::ParserError
      {}
    end
  end
end
