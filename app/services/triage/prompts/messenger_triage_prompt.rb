module Triage
  module Prompts
    class MessengerTriagePrompt
      def initialize(email, layer_results)
        @email = email
        @layer_results = layer_results
      end

      def build
        <<~PROMPT
          Você é um analista de segurança digital especializado em mensagens de aplicativos de mensagens (WhatsApp, Telegram, Signal, etc.).

          Um usuário recebeu uma mensagem suspeita em um aplicativo de mensagens e encaminhou o conteúdo por e-mail para análise. Sua tarefa é avaliar se o conteúdo é seguro ou perigoso.

          ## Conteúdo da Mensagem
          - **Remetente original**: #{@email.from_name} <#{@email.from_address}>
          - **Assunto**: #{@email.subject}

          ```
          #{truncate_text(@email.body_text, 3000)}
          ```

          ## URLs Encontradas (#{(@email.extracted_urls || []).size} no total)
          #{format_urls}

          ## Anexos
          #{format_attachments}

          ## Resultados da Verificação Automática
          #{format_layer_results}

          ## Sua Tarefa
          Analise TODOS os dados acima e forneça sua avaliação como um objeto JSON com exatamente estes campos:
          - **score**: inteiro 0-100 (0 = certamente seguro, 100 = certamente perigoso)
          - **verdict**: um de "legitimate", "suspicious_likely_ok", "suspicious_likely_fraud", "fraudulent"
          - **confidence**: float 0.0-1.0 (quão confiante você está no seu veredito)
          - **reasoning**: uma conclusão curta e direta (1-3 frases)
          - **key_findings**: array de strings, as 3-5 descobertas mais importantes
          - **safety_recommendation**: string, recomendação prática para o usuário sobre o que fazer (1-2 frases)

          Foque em:
          1. Links perigosos (phishing, malware, domínios suspeitos)
          2. Golpes comuns em mensageiros (falsas promoções, falso suporte técnico, engenharia social)
          3. Tentativas de roubo de credenciais ou dados pessoais
          4. Arquivos potencialmente maliciosos

          Responda em português brasileiro. Responda APENAS com o objeto JSON, nenhum outro texto.
        PROMPT
      end

      private

      def truncate_text(text, max_length)
        return "Nenhum conteúdo de texto disponível" if text.blank?

        if text.length > max_length
          text[0...max_length] + "\n... [truncado]"
        else
          text
        end
      end

      def format_urls
        urls = (@email.extracted_urls || []).first(25)
        return "Nenhuma URL encontrada" if urls.empty?

        urls.map { |u| "- #{u}" }.join("\n")
      end

      def format_attachments
        attachments = @email.attachments_info || []
        return "Sem anexos" if attachments.empty?

        attachments.map { |a| "- #{a['filename']} (#{a['content_type']}, #{a['size']} bytes)" }.join("\n")
      end

      def format_layer_results
        @layer_results.map do |layer|
          <<~LAYER
            ### #{layer.layer_name.titleize} (Pontuação: #{layer.score}/100, Confiança: #{layer.confidence})
            #{layer.explanation}
          LAYER
        end.join("\n")
      end
    end
  end
end
