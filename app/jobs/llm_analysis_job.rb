class LlmAnalysisJob < ApplicationJob
  queue_as :llm

  def perform(email_id)
    email = Email.find(email_id)
    Analysis::LlmAnalyzer.new(email).analyze
  rescue => e
    mark_layer_failed(email_id, "llm_analysis", e)
    Analysis::PipelineOrchestrator.advance(email) if email
    raise
  end
end
