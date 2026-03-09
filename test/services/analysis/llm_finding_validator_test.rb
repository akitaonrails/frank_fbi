require "test_helper"

class Analysis::LlmFindingValidatorTest < ActiveSupport::TestCase
  setup do
    @email = create(:email)
  end

  # --- Blacklist claims ---

  test "strips blacklist claim when actual blacklist_hits is 0" do
    create(:analysis_layer, :sender_reputation, :completed,
      email: @email,
      details: { "blacklist_hits" => 0, "blacklist_results" => {} })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = ["Domínio listado em 3 listas negras (Spamhaus DBL, URIBL Multi, Spamhaus ZEN)"]
    result = validator.validate_findings(findings)

    assert_empty result, "Blacklist claim should be stripped when actual hits = 0"
  end

  test "keeps blacklist claim when actual blacklist_hits is positive" do
    create(:analysis_layer, :sender_reputation, :completed,
      email: @email,
      details: { "blacklist_hits" => 2, "blacklist_results" => {} })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = ["Domínio listado em 2 listas negras"]
    result = validator.validate_findings(findings)

    assert_equal 1, result.size
    assert_equal "Domínio listado em 2 listas negras", result.first
  end

  test "strips Spamhaus-specific claim when blacklist_hits is 0" do
    create(:analysis_layer, :sender_reputation, :completed,
      email: @email,
      details: { "blacklist_hits" => 0 })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = ["Remetente listado no Spamhaus ZEN"]
    result = validator.validate_findings(findings)

    assert_empty result
  end

  test "annotates blacklist claim with [Não verificado] when sender_reputation layer missing" do
    validator = Analysis::LlmFindingValidator.new(@email)
    findings = ["Domínio em blacklist do Spamhaus"]
    result = validator.validate_findings(findings)

    assert_equal 1, result.size
    assert_match /\[Não verificado\]/, result.first
  end

  # --- URL malicious claims ---

  test "strips URL malicious claim when actual detections are 0" do
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: { "virustotal_malicious_count" => 0, "urlhaus_malicious_count" => 0 })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = ["URLs maliciosas detectadas pelo VirusTotal"]
    result = validator.validate_findings(findings)

    assert_empty result
  end

  test "keeps URL malicious claim when VirusTotal detections are positive" do
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: { "virustotal_malicious_count" => 3, "urlhaus_malicious_count" => 0 })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = ["URLs maliciosas identificadas"]
    result = validator.validate_findings(findings)

    assert_equal 1, result.size
  end

  test "keeps URL malicious claim when URLhaus detections are positive" do
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: { "virustotal_malicious_count" => 0, "urlhaus_malicious_count" => 1 })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = ["URL perigosa encontrada no URLhaus"]
    result = validator.validate_findings(findings)

    assert_equal 1, result.size
  end

  # --- Attachment claims ---

  test "strips attachment malicious claim when actual detections are 0" do
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: { "attachments_malicious_count" => 0 })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = ["Anexo malicioso detectado"]
    result = validator.validate_findings(findings)

    assert_empty result
  end

  test "keeps attachment claim when detections are positive" do
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: { "attachments_malicious_count" => 1 })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = ["Anexo malicioso detectado"]
    result = validator.validate_findings(findings)

    assert_equal 1, result.size
  end

  # --- Generic findings ---

  test "passes through generic findings untouched" do
    create(:analysis_layer, :sender_reputation, :completed,
      email: @email,
      details: { "blacklist_hits" => 0 })
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: { "virustotal_malicious_count" => 0, "urlhaus_malicious_count" => 0 })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = [
      "E-mail contém linguagem de urgência",
      "Solicitação de dados pessoais",
      "Reply-To diverge do remetente"
    ]
    result = validator.validate_findings(findings)

    assert_equal 3, result.size
    assert_equal findings, result
  end

  # --- Mixed findings ---

  test "validates mixed findings correctly — strips hallucinations, keeps valid" do
    create(:analysis_layer, :sender_reputation, :completed,
      email: @email,
      details: { "blacklist_hits" => 0 })
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: { "virustotal_malicious_count" => 2, "urlhaus_malicious_count" => 0 })

    validator = Analysis::LlmFindingValidator.new(@email)
    findings = [
      "Domínio listado em listas negras",
      "URLs maliciosas detectadas",
      "Linguagem de urgência no corpo do e-mail"
    ]
    result = validator.validate_findings(findings)

    assert_equal 2, result.size
    assert_not_includes result, "Domínio listado em listas negras"
    assert_includes result, "URLs maliciosas detectadas"
    assert_includes result, "Linguagem de urgência no corpo do e-mail"
  end

  # --- Edge cases ---

  test "handles nil findings gracefully" do
    validator = Analysis::LlmFindingValidator.new(@email)
    assert_nil validator.validate_findings(nil)
  end

  test "handles empty findings array" do
    validator = Analysis::LlmFindingValidator.new(@email)
    assert_equal [], validator.validate_findings([])
  end
end
