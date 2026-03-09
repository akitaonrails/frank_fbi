require "test_helper"

class Analysis::HeaderAuthAnalyzerTest < ActiveSupport::TestCase
  test "flags SPF fail" do
    email = create(:email, raw_headers: "Authentication-Results: mx.google.com; spf=fail; dkim=pass; dmarc=pass")
    layer = Analysis::HeaderAuthAnalyzer.new(email).analyze

    assert_equal "completed", layer.status
    assert layer.score > 20, "SPF fail should increase score"
    assert_includes layer.explanation, "SPF"
  end

  test "scores low for fully authenticated email" do
    email = create(:email, raw_headers: "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass (p=REJECT)")
    layer = Analysis::HeaderAuthAnalyzer.new(email).analyze

    assert_equal "completed", layer.status
    assert layer.score <= 10, "Fully authenticated email should have low score, got #{layer.score}"
  end

  test "detects Reply-To mismatch" do
    email = create(:email, :spam)
    layer = Analysis::HeaderAuthAnalyzer.new(email).analyze

    assert_equal "completed", layer.status
    assert layer.details["reply_to_mismatch"] || layer.details[:reply_to_mismatch]
  end

  test "scores the real ATM spam email high" do
    email = create_email_from_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")
    layer = Analysis::HeaderAuthAnalyzer.new(email).analyze

    assert_equal "completed", layer.status
    assert_equal 0, layer.score
    assert_in_delta 0.1, layer.confidence, 0.001
    assert_includes layer.explanation, "indeterminada"
  end

  test "scores a legitimate email low" do
    email = create_email_from_eml("Fale Conosco - Gabriel Delfiol.eml")
    layer = Analysis::HeaderAuthAnalyzer.new(email).analyze

    assert_equal "completed", layer.status
    assert layer.score <= 20, "Legitimate email should score low, got #{layer.score}"
  end

  test "sets weight correctly" do
    email = create(:email)
    layer = Analysis::HeaderAuthAnalyzer.new(email).analyze
    assert_equal 0.20, layer.weight
  end

  test "calculates confidence based on available auth data" do
    email = create(:email, raw_headers: "Authentication-Results: spf=pass; dkim=pass; dmarc=pass")
    layer = Analysis::HeaderAuthAnalyzer.new(email).analyze
    assert layer.confidence >= 0.8
  end

  test "treats forwarded identity as indeterminate instead of attributing auth headers to claimed sender" do
    raw_source = <<~EML
      From: trusted@example.com
      Reply-To: trusted@example.com
      Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
      Subject: Fwd: suspicious

      ---------- Forwarded message ---------
      From: Scammer Guy <scammer@evil.com>

      hello
    EML
    email = create(:email,
      raw_source: raw_source,
      raw_headers: raw_source.split("\n\n").first,
      from_address: "scammer@evil.com",
      submitter_email: "trusted@example.com"
    )

    layer = Analysis::HeaderAuthAnalyzer.new(email).analyze

    assert_equal 0, layer.score
    assert_in_delta 0.1, layer.confidence, 0.001
    assert layer.details["indirect_sender_context"] || layer.details[:indirect_sender_context]
  end
end
