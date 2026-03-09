require "test_helper"

class Analysis::ContentAnalyzerTest < ActiveSupport::TestCase
  test "detects urgency language" do
    email = create(:email, body_text: "Act now! Your account will be suspended immediately if you don't verify your identity within 24 hours!")
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert_equal "completed", layer.status
    assert layer.score > 15, "Urgency language should increase score"
    assert (layer.details["urgency_matches"] || layer.details[:urgency_matches]).to_i > 0
  end

  test "detects financial fraud patterns" do
    email = create(:email, body_text: "You have won the lottery! Wire transfer of $2.5 million USD to your bank account. Send your bank account number.")
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert layer.score > 20, "Financial fraud patterns should score high, got #{layer.score}"
  end

  test "detects authority impersonation" do
    email = create(:email, body_text: "This is from the FBI. The United Nations has approved your compensation payment.")
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert (layer.details["authority_matches"] || layer.details[:authority_matches]).to_i > 0
  end

  test "detects PII requests" do
    email = create(:email, body_text: "Please send your social security number and credit card number to verify your identity.")
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert (layer.details["pii_request_matches"] || layer.details[:pii_request_matches]).to_i > 0
  end

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

  test "scores the ATM spam email high" do
    email = create_email_from_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert layer.score >= 50, "ATM spam should score high on content, got #{layer.score}"
  end

  test "scores clean email low" do
    email = create(:email, :legitimate, extracted_urls: [])
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert layer.score <= 20, "Clean email should score low, got #{layer.score}"
  end

  test "forwarded email excludes submitter signature from pattern matching" do
    body = <<~TEXT
      ---------- Forwarded message ---------
      From: Scammer <scammer@evil.com>
      Date: Fri, Mar 6, 2026

      Hello, this is a normal message.

      --
      FBI Agent John Smith
      Department of Justice
      Verify your identity within 24 hours
    TEXT

    email = create(:email, body_text: body, subject: "Fwd: Hello")
    layer = Analysis::ContentAnalyzer.new(email).analyze

    # The authority impersonation and urgency patterns are in the submitter's
    # signature, not in the suspect's content — they should NOT be detected
    assert_equal 0, (layer.details["authority_matches"] || layer.details[:authority_matches]).to_i,
      "Authority patterns in submitter signature should not be detected"
    assert_equal 0, (layer.details["urgency_matches"] || layer.details[:urgency_matches]).to_i,
      "Urgency patterns in submitter signature should not be detected"
  end

  test "scores capped at 100" do
    email = create(:email,
      subject: "URGENT!!! ACT NOW!!! YOUR ACCOUNT SUSPENDED!!!",
      body_text: "FBI CIA United Nations lottery winner $5 million. Send social security credit card password bank account wire transfer immediately!",
      extracted_urls: ["https://bit.ly/a", "https://tinyurl.com/b"],
      attachments_info: [{ "filename" => "invoice.pdf.exe", "content_type" => "application/octet-stream", "size" => 1000 }]
    )
    layer = Analysis::ContentAnalyzer.new(email).analyze

    assert layer.score <= 100
  end
end
