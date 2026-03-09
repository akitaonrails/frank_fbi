class CommunityReportingJob < ApplicationJob
  queue_as :default

  def perform(email_id)
    email = Email.find(email_id)
    CommunityReporting::Reporter.new(email).report
  rescue => e
    Rails.logger.error("CommunityReportingJob failed for email #{email_id}: #{e.message}")
    # Don't re-raise — community reporting is best-effort, should never block pipeline
  end
end
