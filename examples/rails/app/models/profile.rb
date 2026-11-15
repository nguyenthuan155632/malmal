# frozen_string_literal: true

# An avatar is never kept as it was uploaded: it is written anew from its
# pixels, so metadata and anything hidden after the image are gone.
class Profile < ApplicationRecord
  has_one_attached :avatar
  sanitizes_attachment :avatar, types: %i[jpeg png gif webp]
end
