class ContentAnalysisJob < ApplicationJob
  queue_as :analysis

  def perform(email_id)
    email = Email.find(email_id)
    Analysis::ContentAnalyzer.new(email).analyze
    Analysis::PipelineOrchestrator.advance(email)
  rescue => e
    mark_layer_failed(email_id, "content_analysis", e)
    Analysis::PipelineOrchestrator.advance(email) if email
    raise
  end
end
