require "test_helper"

class EmailTest < ActiveSupport::TestCase
  test "validates required fields" do
    email = Email.new
    assert_not email.valid?
    assert_includes email.errors[:message_id], "can't be blank"
    assert_includes email.errors[:submitter_email], "can't be blank"
  end

  test "validates message_id uniqueness" do
    create(:email, message_id: "unique@test.com")
    duplicate = build(:email, message_id: "unique@test.com")
    assert_not duplicate.valid?
  end

  test "validates status values" do
    email = build(:email, status: "invalid")
    assert_not email.valid?
    assert_includes email.errors[:status], "is not included in the list"
  end

  test "validates verdict values" do
    email = build(:email, verdict: "invalid")
    assert_not email.valid?

    %w[legitimate suspicious_likely_ok suspicious_likely_fraud fraudulent].each do |v|
      email = build(:email, verdict: v)
      assert email.valid?, "#{v} should be valid"
    end
  end

  test "validates final_score range" do
    assert build(:email, final_score: 0).valid?
    assert build(:email, final_score: 100).valid?
    assert_not build(:email, final_score: -1).valid?
    assert_not build(:email, final_score: 101).valid?
  end

  test "has_many analysis_layers" do
    email = create(:email)
    layer = create(:analysis_layer, email: email, layer_name: "header_auth")
    assert_includes email.analysis_layers, layer
  end

  test "encrypts submitter_email" do
    email = create(:email, submitter_email: "secret@example.com")
    assert_equal "secret@example.com", email.submitter_email
    # Can query with deterministic encryption
    found = Email.find_by(submitter_email: "secret@example.com")
    assert_equal email.id, found.id
  end

  test "encrypts body_text at rest but decrypts transparently" do
    email = create(:email, body_text: "Sensitive PII content: CPF 123.456.789-00")
    email.reload

    # Accessible via model
    assert_equal "Sensitive PII content: CPF 123.456.789-00", email.body_text

    # Encrypted in raw database — ciphertext_for returns the encrypted value
    raw = email.ciphertext_for(:body_text)
    assert_not_equal "Sensitive PII content: CPF 123.456.789-00", raw
    assert raw.present?, "body_text should be encrypted at rest"
  end

  test "encrypts body_html at rest but decrypts transparently" do
    email = create(:email, body_html: "<p>Dados sensíveis: conta bancária 12345</p>")
    email.reload

    assert_equal "<p>Dados sensíveis: conta bancária 12345</p>", email.body_html

    raw = email.ciphertext_for(:body_html)
    assert_not_equal "<p>Dados sensíveis: conta bancária 12345</p>", raw
    assert raw.present?, "body_html should be encrypted at rest"
  end

  test "fully_analyzed? returns true when all pipeline layers completed" do
    email = create(:email)
    email.pipeline_layer_names.each do |name|
      create(:analysis_layer, :completed, email: email, layer_name: name, weight: AnalysisLayer.default_weight(name))
    end
    assert email.fully_analyzed?
  end

  test "fully_analyzed? returns false when layers incomplete" do
    email = create(:email)
    create(:analysis_layer, :completed, email: email, layer_name: "header_auth")
    assert_not email.fully_analyzed?
  end
end
