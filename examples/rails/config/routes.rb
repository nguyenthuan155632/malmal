# frozen_string_literal: true

Rails.application.routes.draw do
  root "uploads#index"
  post "documents", to: "uploads#document"
  post "avatars", to: "uploads#avatar"
end
