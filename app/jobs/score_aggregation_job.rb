class ScoreAggregationJob < ApplicationJob
  queue_as :default

  def perform(email_id)
    email = Email.find(email_id)
    Analysis::ScoreAggregator.new(email).aggregate
    ReportGenerationJob.perform_later(email.id)
  rescue => e
    email&.update(status: "failed")
    Rails.logger.error("ScoreAggregationJob failed for email #{email_id}: #{e.message}")
    raise
  end
end
