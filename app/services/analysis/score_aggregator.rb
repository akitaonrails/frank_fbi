module Analysis
  class ScoreAggregator
    VERDICT_THRESHOLDS = {
      (0..25) => "legitimate",
      (26..50) => "suspicious_likely_ok",
      (51..75) => "suspicious_likely_fraud",
      (76..100) => "fraudulent"
    }.freeze

    def initialize(email)
      @email = email
    end

    def aggregate
      final_score = nil
      verdict = nil

      @email.with_lock do
        # Prevent double aggregation from concurrent ScoreAggregationJobs
        return { score: @email.final_score, verdict: @email.verdict } if @email.final_score.present?

        layers = @email.analysis_layers.where(status: "completed")
        return nil if layers.empty?

        escalation = RiskEscalationPolicy.new(layers).evaluate
        final_score = calculate_weighted_score(layers, escalation[:floor])
        verdict = score_to_verdict(final_score)

        @email.update!(
          final_score: final_score,
          verdict: verdict,
          verdict_explanation: build_verdict_explanation(layers, final_score, verdict, escalation[:reasons]),
          analyzed_at: Time.current
        )
      end

      # These run outside the lock — they update other records
      update_reputation_records(verdict)
      encrypt_if_legitimate(verdict)

      { score: final_score, verdict: verdict }
    end

    private

    def calculate_weighted_score(layers, escalation_floor)
      weighted_sum = 0.0
      weight_sum = 0.0

      layers.each do |layer|
        effective_weight = layer.weight * layer.confidence
        weighted_sum += layer.score * effective_weight
        weight_sum += effective_weight
      end

      return 50 if weight_sum.zero?
      blended_score = (weighted_sum / weight_sum).round
      [blended_score, escalation_floor].max
    end

    def score_to_verdict(score)
      VERDICT_THRESHOLDS.each do |range, verdict|
        return verdict if range.include?(score)
      end
      "suspicious_likely_fraud"
    end

    def build_verdict_explanation(layers, score, verdict, escalation_reasons = [])
      lines = ["Pontuação Final: #{score}/100 — #{verdict.humanize}"]
      lines << ""

      if escalation_reasons.any?
        lines << "Gatilhos de escalonamento:"
        escalation_reasons.each { |reason| lines << "- #{reason}" }
        lines << ""
      end

      layers.order(:layer_name).each do |layer|
        lines << "#{layer.layer_name.titleize}: #{layer.score}/100 (weight: #{layer.weight}, confidence: #{layer.confidence})"
        lines << "  #{layer.explanation}"
        lines << ""
      end

      lines.join("\n")
    end

    def update_reputation_records(verdict)
      # Local reputation needs confirmed labels, not feedback from the model itself.
      # We still keep KnownDomain/KnownSender records for caching and operator workflows,
      # but the automated verdict is not written back as truth.
    end

    def encrypt_if_legitimate(verdict)
      return unless verdict == "legitimate"

      # For legitimate emails, encrypt the body content to protect privacy
      # We re-save with encryption applied
      @email.class.encrypts :body_text
      @email.class.encrypts :body_html
      @email.save!
    rescue => e
      Rails.logger.warn("ScoreAggregator: Failed to encrypt legitimate email body: #{e.message}")
    end
  end
end
