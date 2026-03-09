require "test_helper"

class Analysis::EntityExtractionServiceTest < ActiveSupport::TestCase
  test "extracts sender info" do
    email = create(:email, from_name: "Dr. James Smith", from_address: "james@example.com",
                   sender_domain: "example.com", reply_to_address: "reply@other.com")

    result = Analysis::EntityExtractionService.new(email).extract

    assert_equal "Dr. James Smith", result[:sender][:name]
    assert_equal "james@example.com", result[:sender][:email]
    assert_equal "example.com", result[:sender][:domain]
    assert_equal "reply@other.com", result[:sender][:reply_to]
  end

  test "skips person research for generic senders" do
    %w[noreply@example.com info@company.com support@test.com contact@org.com].each do |addr|
      email = create(:email, from_address: addr)
      result = Analysis::EntityExtractionService.new(email).extract
      assert result[:skip_person_research], "Should skip person research for #{addr}"
    end
  end

  test "does not skip person research for regular senders" do
    email = create(:email, from_address: "john.smith@example.com")
    result = Analysis::EntityExtractionService.new(email).extract
    assert_not result[:skip_person_research]
  end

  test "detects freemail senders" do
    email = create(:email, sender_domain: "gmail.com")
    result = Analysis::EntityExtractionService.new(email).extract
    assert result[:freemail]
  end

  test "does not flag non-freemail domains" do
    email = create(:email, sender_domain: "fbi.gov")
    result = Analysis::EntityExtractionService.new(email).extract
    assert_not result[:freemail]
  end

  test "extracts government agency claims" do
    email = create(:email, body_text: "This is the FBI. Your Federal Bureau of Investigation case is pending. Contact the Department of Justice.")
    result = Analysis::EntityExtractionService.new(email).extract

    assert result[:claimed_entities][:authority_claims].any?, "Should detect government authority claims"
  end

  test "extracts titled persons" do
    email = create(:email, body_text: "Please contact Dr. James Wilson at the office. Agent Robert Smith will handle your case.")
    result = Analysis::EntityExtractionService.new(email).extract

    assert result[:claimed_entities][:people].any?, "Should extract titled persons"
  end

  test "extracts corporate names" do
    email = create(:email, body_text: "Global Finance Corp. and Western Union Holdings have approved your transfer.")
    result = Analysis::EntityExtractionService.new(email).extract

    assert result[:claimed_entities][:organizations].any?, "Should extract corporate names"
  end

  test "adds sender name if it looks like a person name" do
    email = create(:email, from_name: "James Wilson", body_text: "Hello")
    result = Analysis::EntityExtractionService.new(email).extract

    assert_includes result[:claimed_entities][:people], "James Wilson"
  end

  test "does not add non-person sender names" do
    email = create(:email, from_name: "FBI", body_text: "Hello")
    result = Analysis::EntityExtractionService.new(email).extract

    assert_not_includes result[:claimed_entities][:people], "FBI"
  end

  test "extracts mentioned URLs and emails" do
    email = create(:email,
                   extracted_urls: ["https://example.com", "https://phishing.com"],
                   extracted_emails: ["contact@evil.com"])
    result = Analysis::EntityExtractionService.new(email).extract

    assert_equal 2, result[:mentioned_contacts][:urls].size
    assert_equal 1, result[:mentioned_contacts][:emails].size
  end

  test "works with real ATM spam email" do
    email = create_email_from_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")
    result = Analysis::EntityExtractionService.new(email).extract

    assert result[:claimed_entities][:authority_claims].any?,
           "ATM spam should have authority claims (FBI mentioned)"
  end
end
