# frozen_string_literal: true

class UploadsController < ApplicationController
  def index
    @documents = Document.with_attached_file.order(id: :desc).limit(10)
    @profiles = Profile.with_attached_avatar.order(id: :desc).limit(10)
  end

  def document
    document = Document.new(file: params[:file])
    if document.save
      redirect_to root_path, notice: "#{document.file.filename} was accepted."
    else
      redirect_to root_path, alert: refusal(document, :file)
    end
  end

  def avatar
    profile = Profile.new(avatar: params[:avatar])
    if profile.save
      redirect_to root_path, notice: "The avatar was rebuilt as #{profile.avatar.filename}."
    else
      redirect_to root_path, alert: refusal(profile, :avatar)
    end
  end

  private

  # The message, and the finding codes that explain it.
  def refusal(record, attribute)
    codes = record.errors.details[attribute].flat_map { |detail| detail[:codes] || [] }.uniq
    message = record.errors.full_messages_for(attribute).to_sentence
    codes.empty? ? message : "#{message} (#{codes.join(", ")})"
  end
end
