require "json"

class TriageLlmConsultationJob < ApplicationJob
  queue_as :llm

  retry_on StandardError, wait: :polynomially_longer, attempts: 2

  def perform(email_id, provider, model_id, prompt_or_system, user_content = nil)
    email = Email.find(email_id)

    start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    chat = RubyLLM.chat(model: model_id)
    if user_content
      chat.with_instructions(prompt_or_system)
      response = chat.ask(user_content)
    else
      response = chat.ask(prompt_or_system)
    end

    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time

    parsed = parse_llm_response(response.content)

    verdict = email.llm_verdicts.find_or_initialize_by(provider: provider)
    verdict.update!(
      model_id: model_id,
      score: parsed[:score],
      verdict: parsed[:verdict],
      reasoning: parsed[:reasoning],
      key_findings: parsed[:key_findings],
      confidence: parsed[:confidence],
      content_patterns: {},
      prompt_tokens: response.input_tokens,
      completion_tokens: response.output_tokens,
      response_time_seconds: elapsed.round(2)
    )

    Triage::LlmAnalyzer.finalize(email, verdict)
  rescue => e
    Rails.logger.error("TriageLlmConsultationJob failed for #{provider}: #{e.message}")
    record_failure(email_id, provider, model_id, e)
    # Finalize with a nil-scored verdict so pipeline can continue
    email = Email.find_by(id: email_id)
    if email
      verdict = email.llm_verdicts.find_by(provider: provider)
      Triage::LlmAnalyzer.finalize(email, verdict) if verdict
    end
  end

  private

  def parse_llm_response(content)
    data = extract_json(content)

    {
      score: data["score"]&.to_i&.clamp(0, 100) || 50,
      verdict: validate_verdict(data["verdict"]),
      confidence: data["confidence"]&.to_f&.clamp(0.0, 1.0) || 0.5,
      reasoning: [data["reasoning"].to_s, data["safety_recommendation"].to_s].reject(&:blank?).join(" "),
      key_findings: Array(data["key_findings"]).map(&:to_s).first(10)
    }
  rescue JSON::ParserError => e
    Rails.logger.warn("TriageLlmConsultationJob: Failed to parse JSON: #{e.message}")
    {
      score: 50,
      verdict: "suspicious_likely_fraud",
      confidence: 0.3,
      reasoning: "Falha ao interpretar resposta da IA.",
      key_findings: ["LLM response parsing failed"]
    }
  end

  def extract_json(text)
    text = text.to_s

    if text =~ /```json\s*(.*?)```/mi
      begin
        return JSON.parse($1.strip)
      rescue JSON::ParserError
      end
    end

    start_idx = text.index("{")
    end_idx = text.rindex("}")
    if start_idx && end_idx && end_idx > start_idx
      begin
        return JSON.parse(text[start_idx..end_idx])
      rescue JSON::ParserError
      end
    end

    JSON.parse(text.strip)
  end

  def validate_verdict(verdict)
    valid = %w[legitimate suspicious_likely_ok suspicious_likely_fraud fraudulent]
    return verdict if valid.include?(verdict)

    case verdict&.downcase
    when /legit/ then "legitimate"
    when /fraud/ then "fraudulent"
    when /suspicious.*ok/, /likely.*ok/ then "suspicious_likely_ok"
    when /suspicious/, /likely.*fraud/ then "suspicious_likely_fraud"
    else "suspicious_likely_fraud"
    end
  end

  def record_failure(email_id, provider, model_id, error)
    email = Email.find_by(id: email_id)
    return unless email

    verdict = email.llm_verdicts.find_or_initialize_by(provider: provider)
    verdict.update(
      model_id: model_id,
      score: nil,
      reasoning: "Error: #{error.message}"
    )
  end
end
