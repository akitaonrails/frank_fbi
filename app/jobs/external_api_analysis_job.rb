class ExternalApiAnalysisJob < ApplicationJob
  queue_as :external_api

  def perform(email_id)
    email = Email.find(email_id)
    Analysis::ExternalApiAnalyzer.new(email).analyze
    Analysis::PipelineOrchestrator.advance(email)
  rescue => e
    mark_layer_failed(email_id, "external_api", e)
    Analysis::PipelineOrchestrator.advance(email) if email
    raise
  end

  private

  def mark_layer_failed(email_id, layer_name, error)
    email = Email.find_by(id: email_id)
    return unless email

    layer = email.analysis_layers.find_or_initialize_by(layer_name: layer_name)
    layer.update(status: "failed", details: { error: error.message })
  end
end
