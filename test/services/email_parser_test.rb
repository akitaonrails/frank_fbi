require "test_helper"

class EmailParserTest < ActiveSupport::TestCase
  test "parses ATM spam email" do
    raw = read_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")
    parser = EmailParser.new(raw)
    result = parser.parse

    assert_match(/YOUR ATM CARD COMPENSATION PAYMENT/, result[:subject])
    # The body contains "Email: lawyergeraddave00@hotmail.com" — the parser
    # correctly extracts this as the embedded sender (contact form pattern)
    assert_equal "lawyergeraddave00@hotmail.com", result[:from_address]
    assert_equal "lawyergeraddave00@hotmail.com", result[:reply_to_address]
    assert_equal "hotmail.com", result[:sender_domain]
    assert result[:raw_headers].present?
    assert result[:body_text].present?
  end

  test "parses legitimate contact email" do
    raw = read_eml("Fale Conosco - Gabriel Delfiol.eml")
    parser = EmailParser.new(raw)
    result = parser.parse

    assert_match(/Gabriel Delfiol/, result[:subject])
    assert result[:from_address].present?
    assert result[:sender_domain].present?
  end

  test "extracts URLs from email body" do
    raw = read_eml("Seu Pacote UPS foi entregue.eml")
    parser = EmailParser.new(raw)
    result = parser.parse

    assert result[:extracted_urls].is_a?(Array)
  end

  test "extracts message_id" do
    raw = read_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")
    parser = EmailParser.new(raw)
    result = parser.parse

    assert result[:message_id].present?
  end

  test "handles email with attachments" do
    raw = read_eml("APORTE -COMPRA.eml")
    parser = EmailParser.new(raw)
    result = parser.parse

    assert result[:attachments_info].is_a?(Array)
  end

  test "extracts email addresses from body" do
    raw = read_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")
    parser = EmailParser.new(raw)
    result = parser.parse

    assert result[:extracted_emails].is_a?(Array)
  end

  test "generates message_id when missing" do
    raw = "From: test@example.com\nSubject: Test\n\nBody"
    parser = EmailParser.new(raw)
    result = parser.parse

    assert result[:message_id].present?
  end

  # --- Forwarded email detection ---

  test "extracts original sender from Gmail forwarded message" do
    raw = <<~EML
      From: trusted@example.com
      Subject: Fwd: You won a prize
      Message-ID: <fwd-test@example.com>

      ---------- Forwarded message ---------
      From: Scammer Guy <scammer@evil.com>
      Date: Mon, 1 Jan 2026
      Subject: You won a prize

      Click here to claim your prize!
    EML
    result = EmailParser.new(raw).parse

    assert_equal "scammer@evil.com", result[:from_address]
    assert_equal "Scammer Guy", result[:from_name]
    assert_equal "evil.com", result[:sender_domain]
  end

  test "extracts original sender from Outlook forwarded message" do
    raw = <<~EML
      From: trusted@example.com
      Subject: FW: Urgent payment
      Message-ID: <outlook-fwd@example.com>

      -------- Original Message --------
      From: Phisher <phisher@badsite.net>
      Sent: Tuesday, January 2, 2026

      Please wire $5000 immediately.
    EML
    result = EmailParser.new(raw).parse

    assert_equal "phisher@badsite.net", result[:from_address]
    assert_equal "Phisher", result[:from_name]
    assert_equal "badsite.net", result[:sender_domain]
  end

  test "parses forwarded email sent as attached original message" do
    raw = read_eml("original_msg.eml")
    result = EmailParser.new(raw).parse

    assert_equal "suporte-pje-123@pje.jus.br", result[:from_address]
    assert_equal "Suporte-Pje", result[:from_name]
    assert_equal "Andamento Processual Ref: 15098", result[:subject]
    assert_equal "y0jludsl@pje.jus.br", result[:reply_to_address]
    assert_equal "pje.jus.br", result[:sender_domain]
    assert result[:raw_headers].include?("Authentication-Results")
    assert result[:analysis_raw_source].include?("Reply-To: y0jludsl@pje.jus.br")
  end

  # --- Contact form detection ---

  test "extracts sender from contact form with Email: label" do
    raw = <<~EML
      From: contact@mywebsite.com
      Subject: New contact form submission
      Message-ID: <form-1@mywebsite.com>

      Name: John Doe
      Email: suspicious@spammer.org
      Message: I have an amazing business opportunity for you!
    EML
    result = EmailParser.new(raw).parse

    assert_equal "suspicious@spammer.org", result[:from_address]
    assert_equal "John Doe", result[:from_name]
    assert_equal "spammer.org", result[:sender_domain]
  end

  test "extracts sender from contact form with E-mail: label" do
    raw = <<~EML
      From: noreply@mysite.com
      Subject: Contact form
      Message-ID: <form-2@mysite.com>

      Full Name: Jane Smith
      E-mail: jane@suspicious-domain.com
      Phone: 555-1234
      Message: Buy our products now!
    EML
    result = EmailParser.new(raw).parse

    assert_equal "jane@suspicious-domain.com", result[:from_address]
    assert_equal "Jane Smith", result[:from_name]
    assert_equal "suspicious-domain.com", result[:sender_domain]
  end

  test "extracts sender from contact form with Reply email: label" do
    raw = <<~EML
      From: forms@website.com
      Subject: New inquiry
      Message-ID: <form-3@website.com>

      Reply email: fraud@scamsite.net
      Subject: Partnership opportunity
      Body: We want to partner with your company...
    EML
    result = EmailParser.new(raw).parse

    assert_equal "fraud@scamsite.net", result[:from_address]
    assert_equal "scamsite.net", result[:sender_domain]
  end

  test "skips contact form extraction when email matches envelope From" do
    raw = <<~EML
      From: contact@mysite.com
      Subject: Test
      Message-ID: <form-4@mysite.com>

      Email: contact@mysite.com
      Message: Hello
    EML
    result = EmailParser.new(raw).parse

    assert_equal "contact@mysite.com", result[:from_address]
    assert_equal "mysite.com", result[:sender_domain]
  end

  test "extracts sender from real-world contact form with Nome/Email fields" do
    raw = <<~EML
      From: contact@mywebsite.com
      Subject: Mensagem de Larissa
      Message-ID: <form-real@mywebsite.com>

      Nome: Larissa
      Email: l6103933@gmail.com
      Telefone: +55 (11) 99374-4770
      Empresa: Nenhuma
      Como nos conheceu: Google
      Mensagem: Eu queria vender produtos variados
    EML
    result = EmailParser.new(raw).parse

    assert_equal "l6103933@gmail.com", result[:from_address]
    assert_equal "Larissa", result[:from_name]
    assert_equal "gmail.com", result[:sender_domain]
  end

  test "forwarded message takes priority over contact form pattern" do
    raw = <<~EML
      From: trusted@example.com
      Subject: Fwd: Spam from form
      Message-ID: <priority-test@example.com>

      ---------- Forwarded message ---------
      From: Real Spammer <spammer@evil.com>
      Date: Mon, 1 Jan 2026

      Email: decoy@other.com
      Message: This is spam
    EML
    result = EmailParser.new(raw).parse

    assert_equal "spammer@evil.com", result[:from_address]
    assert_equal "Real Spammer", result[:from_name]
  end

  # --- Issue #3: latin-1 / non-UTF8 bodies must not crash on serialization ---

  test "decodes latin-1 body to UTF-8 without raising on JSON serialize" do
    # Pure ISO-8859-1 bytes: "Olá, você está aí?" → \xD3l\xE1, voc\xEA est\xE1 a\xED?
    latin1_body = "Ol\xE1, voc\xEA est\xE1 bem?\r\n".dup.force_encoding("ASCII-8BIT")
    raw = (+<<~EOH).force_encoding("ASCII-8BIT") + latin1_body
      From: cobranca@example.com
      To: vitima@example.com
      Subject: Fatura
      MIME-Version: 1.0
      Content-Type: text/plain; charset=ISO-8859-1
      Content-Transfer-Encoding: 8bit

    EOH
    result = EmailParser.new(raw).parse

    assert result[:body_text].is_a?(String)
    assert result[:body_text].valid_encoding?, "body_text must be valid UTF-8"
    assert_equal Encoding::UTF_8, result[:body_text].encoding
    # Should round-trip through JSON (this is what SolidQueue does internally)
    assert_nothing_raised { JSON.generate(body: result[:body_text]) }
    assert_includes result[:body_text], "Olá"
    assert_includes result[:body_text], "você"
  end

  test "scrubs invalid UTF-8 bytes when charset is mislabeled" do
    raw = <<~EOH.b + "valid then bad: \xC3\x28\r\n".b
      From: a@example.com
      Subject: bad bytes
      Content-Type: text/plain; charset=UTF-8
      Content-Transfer-Encoding: 8bit

    EOH
    result = EmailParser.new(raw).parse

    assert result[:body_text].valid_encoding?
    assert_nothing_raised { JSON.generate(body: result[:body_text]) }
  end

  # --- Issue #4: Gmail "forward as attachment" without .eml filename ---

  test "extracts attached message when Gmail ships it as application/octet-stream without .eml extension" do
    inner = <<~INNER
      From: phisher@evil.example
      To: victim@example.com
      Subject: Click here to verify
      Message-ID: <inner-1@evil.example>
      Date: Mon, 01 Jan 2024 12:00:00 +0000

      Please click https://evil.example/login to verify your account.
    INNER

    raw = <<~OUTER
      From: me@gmail.com
      To: frank@fbi.example
      Subject: Fwd: Click here to verify
      MIME-Version: 1.0
      Content-Type: multipart/mixed; boundary="b"

      --b
      Content-Type: text/plain

      Forwarding this for analysis.

      --b
      Content-Type: application/octet-stream
      Content-Disposition: attachment; filename="forwarded-message"
      Content-Transfer-Encoding: 7bit

      #{inner}
      --b--
    OUTER

    result = EmailParser.new(raw).parse

    assert_equal "phisher@evil.example", result[:from_address]
    assert_equal "Click here to verify", result[:subject]
    assert_equal "evil.example", result[:sender_domain]
  end
end
