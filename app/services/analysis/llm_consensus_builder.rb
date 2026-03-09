module Analysis
  class LlmConsensusBuilder
    VERDICT_WEIGHTS = {
      "fraudulent" => 4,
      "suspicious_likely_fraud" => 3,
      "suspicious_likely_ok" => 2,
      "legitimate" => 1
    }.freeze

    def initialize(verdicts, email: nil)
      @verdicts = verdicts
      @email = email
    end

    def build
      scores = @verdicts.map(&:score)
      confidences = @verdicts.map(&:confidence)
      verdicts_list = @verdicts.map(&:verdict)

      weighted_score = calculate_weighted_score
      majority_verdict = determine_majority_verdict(verdicts_list)
      consensus_confidence = calculate_consensus_confidence(verdicts_list, confidences)
      key_findings = aggregate_key_findings
      content_patterns = aggregate_content_patterns

      {
        score: weighted_score,
        confidence: consensus_confidence,
        explanation: build_explanation(majority_verdict, weighted_score),
        details: {
          individual_scores: @verdicts.map { |v| { provider: v.provider, score: v.score, verdict: v.verdict } },
          majority_verdict: majority_verdict,
          score_spread: scores.max - scores.min,
          key_findings: key_findings,
          content_patterns: content_patterns
        }
      }
    end

    private

    def calculate_weighted_score
      total_weight = 0.0
      weighted_sum = 0.0

      @verdicts.each do |v|
        weight = v.confidence || 0.5
        weighted_sum += v.score * weight
        total_weight += weight
      end

      return 50 if total_weight.zero?
      (weighted_sum / total_weight).round
    end

    def determine_majority_verdict(verdicts_list)
      # Count verdict categories
      counts = verdicts_list.compact.tally
      return "suspicious_likely_fraud" if counts.empty?

      # If there's a clear majority, use it
      max_count = counts.values.max
      majority = counts.select { |_, v| v == max_count }.keys

      if majority.size == 1
        majority.first
      else
        # Tie-breaker: pick the more cautious verdict (higher severity)
        majority.max_by { |v| VERDICT_WEIGHTS[v] || 0 }
      end
    end

    def calculate_consensus_confidence(verdicts_list, confidences)
      # Agreement boosts confidence, disagreement lowers it
      unique_verdicts = verdicts_list.compact.uniq
      avg_confidence = confidences.compact.sum / [confidences.compact.size, 1].max

      if unique_verdicts.size == 1
        # Full agreement
        [avg_confidence + 0.1, 1.0].min
      elsif unique_verdicts.size == 2
        # Partial agreement
        avg_confidence * 0.9
      else
        # Full disagreement
        avg_confidence * 0.7
      end.round(2)
    end

    def aggregate_key_findings
      all_findings = @verdicts.flat_map { |v| v.key_findings || [] }
      findings = all_findings.uniq.first(7)

      # Defense-in-depth: validate aggregated findings against actual layer data
      if @email
        validator = LlmFindingValidator.new(@email)
        findings = validator.validate_findings(findings)
      end

      findings
    end

    def aggregate_content_patterns
      keys = %w[urgency financial_fraud pii_request authority_impersonation phishing]
      keys.each_with_object({}) do |key, result|
        counts = @verdicts.map { |v| (v.content_patterns || {})[key].to_i }
        result[key] = counts.max || 0
      end
    end

    def build_explanation(verdict, score)
      providers = @verdicts.map(&:provider).join(", ")
      agreement = @verdicts.map(&:verdict).uniq.size == 1 ? "unânime" : "majoritário"

      "Veredito #{verdict.humanize.downcase} #{agreement} de #{@verdicts.size} modelos de IA (#{providers}). " \
        "Pontuação de consenso: #{score}/100. " \
        "#{summarize_reasoning}"
    end

    def summarize_reasoning
      # Take the first reasoning that mentions the most findings
      best = @verdicts.max_by { |v| v.reasoning.to_s.length }
      return "" unless best&.reasoning

      # Take first sentence
      best.reasoning.split(/[.!]/).first.to_s.strip + "."
    end
  end
end
