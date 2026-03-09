class TriageLlmJob < ApplicationJob
  queue_as :llm

  def perform(email_id)
    email = Email.find(email_id)
    Triage::LlmAnalyzer.new(email).analyze
  rescue => e
    mark_layer_failed(email_id, "triage_llm", e)
    Triage::PipelineOrchestrator.advance(email) if email
    raise
  end
end
