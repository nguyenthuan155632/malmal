# frozen_string_literal: true

# A document is kept as it was uploaded, once the scanner finds it clean.
class Document < ApplicationRecord
  has_one_attached :file
  validates :file, presence: true, malmal: true
end
