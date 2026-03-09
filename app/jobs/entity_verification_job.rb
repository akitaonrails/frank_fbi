class EntityVerificationJob < ApplicationJob
  queue_as :external_api

  retry_on StandardError, wait: :polynomially_longer, attempts: 2

  def perform(email_id)
    email = Email.find(email_id)
    Analysis::EntityVerificationAnalyzer.new(email).analyze
    Analysis::PipelineOrchestrator.advance(email)
  rescue => e
    mark_layer_failed(email_id, "entity_verification", e)
    Analysis::PipelineOrchestrator.advance(email) if email
    raise
  end
end
