class AdminMailer < ApplicationMailer
  def command_result(to_email, subject, body_html, body_text)
    mail(to: to_email, subject: subject) do |format|
      format.html { render html: body_html.html_safe }
      format.text { render plain: body_text }
    end
  end

  def rejection_notice(to_email, original_subject)
    @original_subject = original_subject

    mail(
      to: to_email,
      subject: "Re: #{original_subject} — Not Authorized"
    ) do |format|
      format.text do
        render plain: "Your email address is not authorized to use this service. Contact the administrator."
      end
      format.html do
        render html: "<p>Your email address is not authorized to use this service. Contact the administrator.</p>".html_safe
      end
    end
  end
end
