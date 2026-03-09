class ApplicationJob < ActiveJob::Base
  # Automatically retry jobs that encountered a deadlock
  # retry_on ActiveRecord::Deadlocked

  # Most jobs are safe to ignore if the underlying records are no longer available
  # discard_on ActiveJob::DeserializationError

  private

  def mark_layer_failed(email_id, layer_name, error)
    email = Email.find_by(id: email_id)
    return unless email

    layer = email.analysis_layers.find_or_initialize_by(layer_name: layer_name)
    layer.update(status: "failed", details: { error: error.message })
  end
end
