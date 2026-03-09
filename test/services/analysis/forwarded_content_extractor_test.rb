require "test_helper"

class Analysis::ForwardedContentExtractorTest < ActiveSupport::TestCase
  test "Gmail forwarding marker extracts suspect text and strips submitter signature" do
    body = <<~TEXT
      ---------- Forwarded message ---------
      From: Scammer <scammer@evil.com>
      Date: Fri, Mar 6, 2026
      Subject: You won!

      Congratulations! You won $1 million. Send your bank account now.

      --
      ===========================
      Fabio Akita - boss@akitaonrails.com
      www.akitaonrails.com
    TEXT

    result = Analysis::ForwardedContentExtractor.new(body).extract

    assert result[:forwarded]
    assert_includes result[:suspect_text], "Congratulations"
    assert_includes result[:suspect_text], "bank account"
    refute_includes result[:suspect_text], "Fabio Akita"
    refute_includes result[:suspect_text], "akitaonrails.com"
    assert_nil result[:submitter_text]
  end

  test "Outlook forwarding marker works" do
    body = <<~TEXT
      ----- Original Message -----
      From: Scammer <scammer@evil.com>
      Date: Fri, Mar 6, 2026

      Click here to claim your prize!

      --
      John Doe
      john@example.com
    TEXT

    result = Analysis::ForwardedContentExtractor.new(body).extract

    assert result[:forwarded]
    assert_includes result[:suspect_text], "Click here to claim your prize"
    refute_includes result[:suspect_text], "John Doe"
    refute_includes result[:suspect_text], "john@example.com"
  end

  test "no forwarding marker returns full body as suspect_text" do
    body = "Hello, this is a regular email with no forwarding."

    result = Analysis::ForwardedContentExtractor.new(body).extract

    refute result[:forwarded]
    assert_equal body, result[:suspect_text]
    assert_nil result[:submitter_text]
  end

  test "forwarded email without trailing signature returns content after marker" do
    body = <<~TEXT
      ---------- Forwarded message ---------
      From: Scammer <scammer@evil.com>
      Date: Fri, Mar 6, 2026

      This is the scam content with no signature below.
    TEXT

    result = Analysis::ForwardedContentExtractor.new(body).extract

    assert result[:forwarded]
    assert_includes result[:suspect_text], "scam content"
  end

  test "preserves submitter commentary before forwarding marker" do
    body = <<~TEXT
      Hey, this looks suspicious to me.

      ---------- Forwarded message ---------
      From: Scammer <scammer@evil.com>

      Send me your password.

      --
      Submitter Sig
    TEXT

    result = Analysis::ForwardedContentExtractor.new(body).extract

    assert result[:forwarded]
    assert_equal "Hey, this looks suspicious to me.", result[:submitter_text]
    assert_includes result[:suspect_text], "Send me your password"
    refute_includes result[:suspect_text], "Submitter Sig"
  end

  test "handles nil body_text" do
    result = Analysis::ForwardedContentExtractor.new(nil).extract

    refute result[:forwarded]
    assert_equal "", result[:suspect_text]
  end

  test "real eml file: submitter signature excluded from suspect text" do
    email = create_email_from_eml("Hola_ Order ID Acknowledgement successfully processed (1).eml")
    result = Analysis::ForwardedContentExtractor.new(email.body_text).extract

    assert result[:forwarded], "Should detect forwarding marker"
    assert_includes result[:suspect_text], "digital invoice"
    refute_includes result[:suspect_text], "Fabio Akita"
    # "akitaonrails.com" may appear in the suspect's To: headers (mass spam target list),
    # but the submitter's signature block (===...Fabio Akita...www.akitaonrails.com) must be stripped
    refute_includes result[:suspect_text], "==========================="
    refute_includes result[:suspect_text], "www.akitaonrails.com"
  end

  test "Portuguese forwarding marker works" do
    body = <<~TEXT
      ---------- Mensagem encaminhada ----------
      De: Golpista <golpista@evil.com>

      Atualize seu cadastro agora!
    TEXT

    result = Analysis::ForwardedContentExtractor.new(body).extract

    assert result[:forwarded]
    assert_includes result[:suspect_text], "Atualize seu cadastro"
  end
end
