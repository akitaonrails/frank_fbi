class AdminMailer < ApplicationMailer
  def command_result(to_email, subject, body_html, body_text)
    mail(to: to_email, subject: subject) do |format|
      format.html { render html: body_html.html_safe }
      format.text { render plain: body_text }
    end
  end

  def rate_limit_notice(to_email, original_subject)
    @original_subject = original_subject

    mail(
      to: to_email,
      subject: "Re: #{original_subject} — Limite de Envios Excedido"
    ) do |format|
      format.text do
        render plain: "Você excedeu o limite de envios por hora. Aguarde um momento e tente novamente mais tarde."
      end
      format.html do
        render html: "<p>Você excedeu o limite de envios por hora. Aguarde um momento e tente novamente mais tarde.</p>".html_safe
      end
    end
  end

  def rejection_notice(to_email, original_subject)
    @original_subject = original_subject

    mail(
      to: to_email,
      subject: "Re: #{original_subject} — Não Autorizado"
    ) do |format|
      format.text do
        render plain: "Seu endereço de e-mail não está autorizado a usar este serviço. Entre em contato com o administrador."
      end
      format.html do
        render html: "<p>Seu endereço de e-mail não está autorizado a usar este serviço. Entre em contato com o administrador.</p>".html_safe
      end
    end
  end
end
