# frozen_string_literal: true

require_relative "malmal/version"
require_relative "malmal/errors"
require_relative "malmal/report"
require_relative "malmal/native"
require_relative "malmal/scanner"
require_relative "malmal/client"

# Checks uploaded images, SVG, PDF and PostScript files before an
# application processes them. Anything but a clean report, including an
# exception, means the file is not accepted.
module Malmal
end
