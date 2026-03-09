class SenderReputationAnalysisJob < ApplicationJob
  queue_as :analysis

  def perform(email_id)
    email = Email.find(email_id)
    Analysis::SenderReputationAnalyzer.new(email).analyze
    Analysis::PipelineOrchestrator.advance(email)
  rescue => e
    mark_layer_failed(email_id, "sender_reputation", e)
    Analysis::PipelineOrchestrator.advance(email) if email
    raise
  end
end
