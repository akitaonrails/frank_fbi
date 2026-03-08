class ReportDeliveryJob < ApplicationJob
  queue_as :default

  retry_on StandardError, wait: 30.seconds, attempts: 3

  def perform(email_id)
    email = Email.find(email_id)
    report = email.analysis_report

    return unless report&.status == "generated"

    report.update!(status: "sending")

    AnalysisReportMailer.report(email).deliver_now

    report.update!(status: "sent", sent_at: Time.current)
    email.update!(status: "completed")
  rescue => e
    report&.update(status: "failed")
    Rails.logger.error("ReportDeliveryJob failed for email #{email_id}: #{e.message}")
    raise
  end
end
