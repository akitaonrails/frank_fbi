require "test_helper"

class MessengerTriageMailboxTest < ActionMailbox::TestCase
  setup do
    ENV["ADMIN_EMAIL"] = "admin@example.com"
    create(:allowed_sender, email_address: "trusted@example.com")
  end

  test "routes messenger content from allowed sender to messenger_triage" do
    inbound = create_inbound_email_from_mail(
      from: "trusted@example.com",
      to: "fbi@example.com",
      subject: "Link suspeito no WhatsApp",
      body: "Recebi isso no grupo: https://wa.me/551199999999"
    )

    assert ApplicationMailbox.send(:messenger_triage?, inbound),
      "Should detect messenger content"
    assert_not ApplicationMailbox.send(:forwarded_email?, inbound),
      "Should NOT detect as forwarded"
  end

  test "routes telegram URL to messenger_triage" do
    inbound = create_inbound_email_from_mail(
      from: "trusted@example.com",
      to: "fbi@example.com",
      subject: "Mensagem estranha",
      body: "Olha esse link: https://t.me/scambot"
    )

    assert ApplicationMailbox.send(:messenger_triage?, inbound)
  end

  test "routes signal URL to messenger_triage" do
    inbound = create_inbound_email_from_mail(
      from: "trusted@example.com",
      to: "fbi@example.com",
      subject: "Recebi no Signal",
      body: "https://signal.me/#p/+5511999999999"
    )

    assert ApplicationMailbox.send(:messenger_triage?, inbound)
  end

  test "routes by subject keyword whatsapp" do
    inbound = create_inbound_email_from_mail(
      from: "trusted@example.com",
      to: "fbi@example.com",
      subject: "Mensagem do WhatsApp suspeita",
      body: "Recebi uma mensagem pedindo dados bancários"
    )

    assert ApplicationMailbox.send(:messenger_triage?, inbound)
  end

  test "routes by subject keyword telegram" do
    inbound = create_inbound_email_from_mail(
      from: "trusted@example.com",
      to: "fbi@example.com",
      subject: "Telegram spam",
      body: "Alguém mandou propaganda estranha"
    )

    assert ApplicationMailbox.send(:messenger_triage?, inbound)
  end

  test "routes by subject keyword zap" do
    inbound = create_inbound_email_from_mail(
      from: "trusted@example.com",
      to: "fbi@example.com",
      subject: "Mensagem do zap",
      body: "Me mandaram um link"
    )

    assert ApplicationMailbox.send(:messenger_triage?, inbound)
  end

  test "forwarded email goes to fraud_analysis not messenger_triage" do
    inbound = create_inbound_email_from_mail(
      from: "trusted@example.com",
      to: "fbi@example.com",
      subject: "Fwd: WhatsApp suspicious",
      body: "---------- Forwarded message ---------\nFrom: scammer@evil.com\nhttps://wa.me/123"
    )

    assert ApplicationMailbox.send(:forwarded_email?, inbound),
      "Should detect as forwarded"
    assert_not ApplicationMailbox.send(:messenger_triage?, inbound),
      "Forwarded email should NOT route to messenger_triage"
  end

  test "messenger_triage mailbox creates email with correct pipeline_type" do
    assert_difference "Email.count", 1 do
      receive_inbound_email_from_mail(
        from: "trusted@example.com",
        to: "fbi@example.com",
        subject: "WhatsApp link suspeito",
        body: "https://wa.me/551199999999"
      )
    end

    email = Email.last
    assert_equal "messenger_triage", email.pipeline_type
    assert_equal "pending", email.status
  end

  test "non-messenger content from allowed sender goes to fraud_analysis" do
    inbound = create_inbound_email_from_mail(
      from: "trusted@example.com",
      to: "fbi@example.com",
      subject: "Check this email",
      body: "Something suspicious happened"
    )

    assert_not ApplicationMailbox.send(:messenger_triage?, inbound)
  end

  test "admin commands still take priority over messenger detection" do
    inbound = create_inbound_email_from_mail(
      from: "admin@example.com",
      to: "fbi@example.com",
      subject: "add whatsapp user",
      body: "add sender@example.com"
    )

    assert ApplicationMailbox.send(:admin_command?, inbound),
      "Admin command should take priority"
  end
end
