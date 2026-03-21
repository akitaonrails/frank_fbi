require "test_helper"

class Analysis::Prompts::FraudAnalysisPromptTest < ActiveSupport::TestCase
  setup do
    @email = create(:email, :spam)
  end

  test "prompt includes anti-hallucination rules" do
    prompt = build_prompt

    assert_includes prompt, "REGRAS OBRIGATÓRIAS"
    assert_includes prompt, "NUNCA invente dados"
    assert_includes prompt, "NUNCA afirme que o domínio está em blacklists"
    assert_includes prompt, "NUNCA afirme que URLs foram detectadas como maliciosas"
    assert_includes prompt, "[Nome da Camada]"
  end

  test "prompt includes structured blacklist data when sender_reputation layer present" do
    create(:analysis_layer, :sender_reputation, :completed,
      email: @email,
      details: { "blacklist_hits" => 0, "domain_age_days" => 1500, "freemail" => false })

    prompt = build_prompt

    assert_includes prompt, "blacklist_hits"
    assert_includes prompt, "Dados estruturados"
    assert_includes prompt, "Hits em listas negras"
  end

  test "prompt includes structured URL data when external_api layer present" do
    create(:analysis_layer, :external_api, :completed,
      email: @email,
      details: {
        "virustotal_malicious_count" => 0,
        "urlhaus_malicious_count" => 0,
        "attachments_malicious_count" => 0,
        "urls_scanned" => 3
      })

    prompt = build_prompt

    assert_includes prompt, "virustotal_malicious_count"
    assert_includes prompt, "urlhaus_malicious_count"
    assert_includes prompt, "attachments_malicious_count"
  end

  test "prompt includes structured header auth data when header_auth layer present" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: {
        "spf_result" => "pass",
        "dkim_result" => "pass",
        "dmarc_result" => "pass",
        "reply_to_mismatch" => true
      })

    prompt = build_prompt

    assert_includes prompt, "SPF: pass"
    assert_includes prompt, "DKIM: pass"
    assert_includes prompt, "DMARC: pass"
    assert_includes prompt, "Reply-To divergente: sim"
  end

  test "prompt works with no prior layers" do
    prompt = build_prompt

    assert_includes prompt, "REGRAS OBRIGATÓRIAS"
    assert_includes prompt, @email.subject
  end

  test "prompt includes key_findings source attribution requirement" do
    prompt = build_prompt

    assert_includes prompt, "CADA item deve começar com \"[Nome da Camada]\""
    assert_includes prompt, "NÃO inclua descobertas sem evidência nas camadas"
  end

  test "build_system contains no email data" do
    layers = @email.analysis_layers.where(status: "completed")
    system_prompt = Analysis::Prompts::FraudAnalysisPrompt.new(@email, layers).build_system

    refute_includes system_prompt, @email.from_address
    refute_includes system_prompt, @email.subject
    assert_includes system_prompt, "REGRAS OBRIGATÓRIAS"
    assert_includes system_prompt, "AVISO CRÍTICO DE SEGURANÇA"
  end

  test "build_user contains raw email source and layer results" do
    create(:analysis_layer, :header_auth, :completed,
      email: @email,
      details: { "spf_result" => "pass" })

    layers = @email.analysis_layers.where(status: "completed")
    user_content = Analysis::Prompts::FraudAnalysisPrompt.new(@email, layers).build_user

    assert_includes user_content, "E-mail bruto (.eml)"
    assert_includes user_content, @email.subject
    assert_includes user_content, "SPF: pass"
  end

  test "system prompt warns about prompt injection techniques" do
    layers = @email.analysis_layers.where(status: "completed")
    system_prompt = Analysis::Prompts::FraudAnalysisPrompt.new(@email, layers).build_system

    assert_includes system_prompt, "Headers ou metadados falsos"
    assert_includes system_prompt, "REGRA MÁXIMA DE DECISÃO"
    assert_includes system_prompt, "Divergência entre as partes MIME"
  end

  private

  def build_prompt
    layers = @email.analysis_layers.where(status: "completed")
    Analysis::Prompts::FraudAnalysisPrompt.new(@email, layers).build
  end
end
