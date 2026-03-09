class ReportGenerationJob < ApplicationJob
  queue_as :default

  def perform(email_id)
    email = Email.find(email_id)
    renderer = email.messenger_triage? ? Triage::ReportRenderer.new(email) : ReportRenderer.new(email)

    report = email.analysis_report || email.build_analysis_report
    report.update!(
      report_html: renderer.to_html,
      report_text: renderer.to_text,
      status: "generated"
    )

    ReportDeliveryJob.perform_later(email.id)
  rescue => e
    Rails.logger.error("ReportGenerationJob failed for email #{email_id}: #{e.message}")
    raise
  end
end
