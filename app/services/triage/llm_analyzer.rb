module Triage
  class LlmAnalyzer
    LAYER_NAME = "triage_llm"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]
    MODEL_PROVIDER = "anthropic"
    MODEL_ID = "anthropic/claude-sonnet-4.6"

    def initialize(email)
      @email = email
    end

    def analyze
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(weight: WEIGHT, status: "running")

      prior_layers = @email.analysis_layers.where(status: "completed").where.not(layer_name: LAYER_NAME)
      prompt = Triage::Prompts::MessengerTriagePrompt.new(@email, prior_layers).build

      TriageLlmConsultationJob.perform_later(@email.id, MODEL_PROVIDER, MODEL_ID, prompt)
    end

    def self.finalize(email, verdict)
      email.with_lock do
        layer = email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
        return if layer.status == "completed"

        if verdict.score.present?
          layer.update!(
            score: verdict.score,
            weight: WEIGHT,
            confidence: verdict.confidence || 0.7,
            details: { provider: verdict.provider, model: verdict.model_id, safety_recommendation: verdict.reasoning },
            explanation: verdict.reasoning,
            status: "completed"
          )
        else
          layer.update!(
            score: 50,
            weight: WEIGHT,
            confidence: 0.0,
            details: { error: "LLM response unusable" },
            explanation: "Análise por IA não produziu resultado utilizável.",
            status: "completed"
          )
        end
      end

      PipelineOrchestrator.advance(email)
    end
  end
end
