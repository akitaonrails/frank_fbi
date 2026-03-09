require "test_helper"

class Analysis::ContentAnalyzerTest < ActiveSupport::TestCase
  test "flags ALL CAPS subject" do
    email = create(:email, subject: "URGENT ACTION REQUIRED NOW!!!", body_text: "Please verify")
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert layer.details["all_caps_subject"] || layer.details[:all_caps_subject]
  end

  test "detects URL shorteners" do
    email = create(:email, extracted_urls: ["https://bit.ly/abc123", "https://tinyurl.com/xyz"])
    layer = Analysis::ContentAnalyzer.new(email).analyze

    shortened = layer.details["shortened_urls"] || layer.details[:shortened_urls]
    assert shortened.present?
    assert_equal 2, shortened.size
  end

  test "scores the ATM spam email on structural signals" do
    email = create_email_from_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")
    layer = Analysis::ContentAnalyzer.new(email).analyze

    # Without regex patterns, score comes from structural checks only
    # (ALL CAPS subject, excessive punctuation, etc.)
    assert layer.score >= 5, "ATM spam should score on structural signals, got #{layer.score}"
    assert_equal "completed", layer.status
  end

  test "scores clean email low" do
    email = create(:email, :legitimate, extracted_urls: [])
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert layer.score <= 20, "Clean email should score low, got #{layer.score}"
  end

  test "forwarded email uses suspect text only" do
    body = <<~TEXT
      ---------- Forwarded message ---------
      From: Scammer <scammer@evil.com>
      Date: Fri, Mar 6, 2026

      Hello, this is a normal message.

      --
      FBI Agent John Smith
      Department of Justice
    TEXT

    email = create(:email, body_text: body, subject: "Fwd: Hello")
    layer = Analysis::ContentAnalyzer.new(email).analyze

    # Should not score high since the suspect content is benign
    assert layer.score <= 20, "Forwarded normal message should score low, got #{layer.score}"
  end

  test "scores capped at 100" do
    email = create(:email,
      subject: "URGENT!!! ACT NOW!!! YOUR ACCOUNT SUSPENDED!!!",
      body_text: "Some text",
      extracted_urls: ["https://bit.ly/a", "https://tinyurl.com/b"],
      attachments_info: [{ "filename" => "invoice.pdf.exe", "content_type" => "application/octet-stream", "size" => 1000 }]
    )
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert layer.score <= 100
  end

  test "detects dangerous attachments" do
    email = create(:email,
      attachments_info: [{ "filename" => "malware.exe", "content_type" => "application/octet-stream", "size" => 5000 }]
    )
    layer = Analysis::ContentAnalyzer.new(email).analyze

    dangerous = layer.details["dangerous_attachments"] || layer.details[:dangerous_attachments]
    assert dangerous.present?
    assert_includes dangerous, "malware.exe"
  end

  test "detects URL text/href mismatches" do
    email = create(:email,
      body_html: '<a href="https://evil.com/steal">https://mybank.com/login</a>',
      body_text: "Click the link"
    )
    layer = Analysis::ContentAnalyzer.new(email).analyze

    mismatches = layer.details["url_mismatches"] || layer.details[:url_mismatches]
    assert mismatches.present?, "Should detect URL mismatch"
  end

  test "detects WhatsApp links" do
    email = create(:email,
      body_text: "Contact us at https://wa.me/5511999999999"
    )
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert (layer.details["whatsapp_matches"] || layer.details[:whatsapp_matches]).to_i > 0
  end

  test "detects broken unsubscribe templates" do
    email = create(:email,
      body_html: '<a href="%%unsubscribelink%%">Unsubscribe</a>',
      body_text: "%%unsubscribelink%%"
    )
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert (layer.details["broken_unsubscribe_matches"] || layer.details[:broken_unsubscribe_matches]).to_i > 0
  end
end
