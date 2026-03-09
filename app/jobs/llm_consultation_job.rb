require "json"

class LlmConsultationJob < ApplicationJob
  queue_as :llm

  retry_on StandardError, wait: :polynomially_longer, attempts: 2

  def perform(email_id, provider, model_id, prompt)
    email = Email.find(email_id)

    start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    chat = RubyLLM.chat(model: model_id)
    response = chat.ask(prompt)

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
      content_patterns: parsed[:content_patterns],
      prompt_tokens: response.input_tokens,
      completion_tokens: response.output_tokens,
      response_time_seconds: elapsed.round(2)
    )

    # Check if all LLM consultations are done
    check_llm_completion(email)
  rescue => e
    Rails.logger.error("LlmConsultationJob failed for #{provider}: #{e.message}")
    record_failure(email_id, provider, model_id, e)
    check_llm_completion(Email.find(email_id))
  end

  private

  def parse_llm_response(content)
    data = extract_json(content)

    {
      score: data["score"]&.to_i&.clamp(0, 100) || 50,
      verdict: validate_verdict(data["verdict"]),
      confidence: data["confidence"]&.to_f&.clamp(0.0, 1.0) || 0.5,
      reasoning: data["reasoning"].to_s,
      key_findings: Array(data["key_findings"]).map(&:to_s).first(10),
      content_patterns: normalize_content_patterns(data["content_patterns"])
    }
  rescue JSON::ParserError => e
    Rails.logger.warn("LlmConsultationJob: Failed to parse JSON from #{content[0..200]}: #{e.message}")
    {
      score: 50,
      verdict: "suspicious_likely_fraud",
      confidence: 0.3,
      reasoning: "Failed to parse LLM response. Raw: #{content.to_s[0..500]}",
      key_findings: ["LLM response parsing failed"],
      content_patterns: {}
    }
  end

  def extract_json(text)
    text = text.to_s

    # Try to find JSON inside ```json ... ``` blocks first
    if text =~ /```json\s*(.*?)```/mi
      begin
        return JSON.parse($1.strip)
      rescue JSON::ParserError
        # Fall through to next strategy
      end
    end

    # Find the first { and match to the last }
    start_idx = text.index("{")
    end_idx = text.rindex("}")
    if start_idx && end_idx && end_idx > start_idx
      begin
        return JSON.parse(text[start_idx..end_idx])
      rescue JSON::ParserError
        # Fall through to last resort
      end
    end

    # Last resort: try parsing the whole thing
    JSON.parse(text.strip)
  end

  def normalize_content_patterns(raw)
    return {} unless raw.is_a?(Hash)

    valid_keys = %w[urgency financial_fraud pii_request authority_impersonation phishing]
    valid_keys.each_with_object({}) do |key, result|
      value = raw[key] || raw[key.to_sym]
      result[key] = [value.to_i, 0].max
    end
  end

  def validate_verdict(verdict)
    valid = %w[legitimate suspicious_likely_ok suspicious_likely_fraud fraudulent]
    return verdict if valid.include?(verdict)

    # Try to map common variations
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

  def check_llm_completion(email)
    total_verdicts = email.llm_verdicts.count
    completed = email.llm_verdicts.where.not(score: nil).count

    # Finalize when we have at least 2 completed or all 3 are done
    if completed >= 2 || total_verdicts >= Analysis::LlmAnalyzer::MODELS.size
      Analysis::LlmAnalyzer.finalize(email)
    end
  end
end
