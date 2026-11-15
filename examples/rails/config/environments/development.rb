# frozen_string_literal: true

Rails.application.configure do
  config.enable_reloading = true
  config.consider_all_requests_local = true
  config.secret_key_base = "development-only-#{"0" * 48}"
end
