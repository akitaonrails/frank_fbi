class AnalysisReportMailer < ApplicationMailer
  def report(email)
    @email = email
    @report = email.analysis_report

    # Thread-aware reply headers
    headers["In-Reply-To"] = "<#{@email.message_id}>"
    headers["References"] = "<#{@email.message_id}>"

    mail(
      to: @email.submitter_email,
      subject: report_subject
    ) do |format|
      format.html { render html: @report.report_html.html_safe }
      format.text { render plain: @report.report_text }
    end
  end

  private

  def report_subject
    verdict_label = case @email.verdict
    when "legitimate" then "[OK]"
    when "suspicious_likely_ok" then "[LIKELY OK]"
    when "suspicious_likely_fraud" then "[SUSPICIOUS]"
    when "fraudulent" then "[FRAUD]"
    else "[ANALYZED]"
    end

    "Re: #{@email.subject} — Frank FBI #{verdict_label} #{@email.final_score}/100"
  end
end
