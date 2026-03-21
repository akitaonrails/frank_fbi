module Analysis
  class LlmAnalyzer
    LAYER_NAME = "llm_analysis"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]

    MODELS = {
      "anthropic" => "anthropic/claude-sonnet-4.6",
      "openai" => "openai/gpt-5.4",
      "xai" => "x-ai/grok-4"
    }.freeze

    def initialize(email)
      @email = email
    end

    def analyze
      # Initialize the layer
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(weight: WEIGHT, status: "running")

      # Build system/user prompts with all previous layer results
      prior_layers = @email.analysis_layers.where(status: "completed").where.not(layer_name: LAYER_NAME)
      prompt_builder = Prompts::FraudAnalysisPrompt.new(@email, prior_layers)
      system_prompt = prompt_builder.build_system
      user_content = prompt_builder.build_user

      # Enqueue parallel LLM consultations with separate system/user messages
      MODELS.each do |provider, model_id|
        LlmConsultationJob.perform_later(@email.id, provider, model_id, system_prompt, user_content)
      end
    end

    def self.finalize(email)
      verdicts = email.llm_verdicts.where.not(score: nil)

      email.with_lock do
        # Re-check inside lock to prevent double finalization
        layer = email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
        return if layer.status == "completed"

        if verdicts.size >= 2
          consensus = LlmConsensusBuilder.new(verdicts.reload, email: email).build

          layer.update!(
            score: consensus[:score],
            weight: WEIGHT,
            confidence: consensus[:confidence],
            details: consensus[:details],
            explanation: consensus[:explanation],
            status: "completed"
          )
        elsif email.llm_verdicts.count >= MODELS.size
          layer.update!(
            score: 50,
            weight: WEIGHT,
            confidence: 0.0,
            details: { error: "Insufficient valid LLM responses", providers_attempted: email.llm_verdicts.pluck(:provider) },
            explanation: "As consultas de IA não produziram consenso utilizável. Camada tratada como indisponível.",
            status: "completed"
          )
        else
          return
        end
      end

      PipelineOrchestrator.advance(email)
    end
  end
end
