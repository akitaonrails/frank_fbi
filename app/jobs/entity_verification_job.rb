class EntityVerificationJob < ApplicationJob
  queue_as :external_api

  retry_on StandardError, wait: :polynomially_longer, attempts: 2

  def perform(email_id)
    email = Email.find(email_id)
    Analysis::EntityVerificationAnalyzer.new(email).analyze
    Analysis::PipelineOrchestrator.advance(email)
  rescue => e
    mark_layer_failed(email_id, e)
    raise
  end

  private

  def mark_layer_failed(email_id, error)
    email = Email.find_by(id: email_id)
    return unless email

    layer = email.analysis_layers.find_or_initialize_by(layer_name: "entity_verification")
    layer.update(status: "failed", details: { error: error.message })
  end
end
