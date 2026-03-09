class HeaderAuthAnalysisJob < ApplicationJob
  queue_as :analysis

  def perform(email_id)
    email = Email.find(email_id)
    Analysis::HeaderAuthAnalyzer.new(email).analyze
    Analysis::PipelineOrchestrator.advance(email)
  rescue => e
    mark_layer_failed(email_id, "header_auth", e)
    Analysis::PipelineOrchestrator.advance(email) if email
    raise
  end
end
