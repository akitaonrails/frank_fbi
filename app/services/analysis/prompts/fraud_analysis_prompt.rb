module Analysis
  module Prompts
    class FraudAnalysisPrompt
      def initialize(email, layer_results)
        @email = email
        @layer_results = layer_results
      end

      def build
        <<~PROMPT
          Você é um analista especialista em fraude de e-mail. Analise o e-mail a seguir e os resultados preliminares da análise para determinar se é fraudulento, suspeito ou legítimo.

          ## Metadados do E-mail
          - **De**: #{@email.from_name} <#{@email.from_address}>
          - **Reply-To**: #{@email.reply_to_address || 'mesmo que De'}
          - **Assunto**: #{@email.subject}
          - **Domínio do Remetente**: #{@email.sender_domain}
          - **Data**: #{@email.received_at}

          ## Corpo do E-mail (texto)
          ```
          #{truncate_text(@email.body_text, 2000)}
          ```

          ## URLs Extraídas (#{(@email.extracted_urls || []).size} no total)
          #{format_urls}

          ## Anexos
          #{format_attachments}

          ## Resultados da Análise Preliminar

          #{format_layer_results}

          ## Sua Tarefa
          Com base em TODAS as informações acima, forneça sua análise de fraude como um objeto JSON com exatamente estes campos:
          - **score**: inteiro 0-100 (0 = certamente legítimo, 100 = certamente fraudulento)
          - **verdict**: um de "legitimate", "suspicious_likely_ok", "suspicious_likely_fraud", "fraudulent"
          - **confidence**: float 0.0-1.0 (quão confiante você está no seu veredito)
          - **reasoning**: uma conclusão curta e direta justificando seu veredito (1-3 frases, sem enrolação)
          - **key_findings**: array de strings, as 3-5 descobertas mais importantes que sustentam seu veredito

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
        urls = (@email.extracted_urls || []).first(15)
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
