require "test_helper"

class EmailParserTest < ActiveSupport::TestCase
  test "parses ATM spam email" do
    raw = read_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")
    parser = EmailParser.new(raw)
    result = parser.parse

    assert_match(/YOUR ATM CARD COMPENSATION PAYMENT/, result[:subject])
    assert_equal "info@asume.gov", result[:from_address]
    assert_equal "FBI", result[:from_name]
    assert_equal "lawyergeraddave00@hotmail.com", result[:reply_to_address]
    assert_equal "asume.gov", result[:sender_domain]
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
end
