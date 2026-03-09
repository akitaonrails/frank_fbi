module Analysis
  module Prompts
    class EntityVerificationPrompt
      def initialize(email, entities)
        @email = email
        @entities = entities
      end

      def build
        <<~PROMPT
          Você é um investigador OSINT verificando a identidade do remetente de um e-mail e das entidades mencionadas em um e-mail suspeito. Seu trabalho é determinar se as pessoas e organizações alegadas neste e-mail realmente existem e correspondem às alegações feitas.

          ## E-mail Sob Investigação
          - **De**: #{@email.from_name} <#{@email.from_address}>
          - **Reply-To**: #{@email.reply_to_address || 'mesmo que De'}
          - **Assunto**: #{@email.subject}
          - **Domínio do Remetente**: #{@email.sender_domain}
          - **Freemail**: #{@entities[:freemail] ? 'Sim' : 'Não'}

          ## Entidades Extraídas
          **Nota**: As entidades abaixo foram extraídas do e-mail do remetente suspeito, não do usuário que encaminhou a mensagem para análise.
          #{format_entities}

          ## Instruções de Pesquisa

          Use a ferramenta brave_web_search para investigar. Orçamento: até 8 buscas.

          **Prioridade da pesquisa:**
          1. **Verificação de domínio**: Busque por "#{@email.sender_domain}" — este domínio pertence à organização alegada? É um site real de empresa/órgão?
          #{person_research_instructions}
          3. **Verificação de organização**: Para cada organização alegada, busque para verificar se ela existe e usa este domínio
          4. **Referência cruzada**: As alegações do remetente correspondem ao que você encontra online?

          **O que procurar:**
          - Perfis LinkedIn correspondendo ao nome do remetente + organização alegada
          - Sites oficiais confirmando que a organização existe
          - Artigos de notícias ou press releases mencionando a entidade
          - Diretórios governamentais para oficiais alegados
          - Registro de domínio correspondendo à organização alegada
          - Sinais de alerta: domínio não corresponde à org, pessoa não tem presença online, org não existe

          ## Formato da Resposta

          Após concluir sua pesquisa, forneça suas descobertas como um objeto JSON com exatamente estes campos:

          ```json
          {
            "score": <inteiro 0-100>,
            "confidence": <float 0.0-1.0>,
            "verdict_summary": "<resumo de 1-2 frases>",
            "sender_verified": <boolean>,
            "domain_verified": <boolean>,
            "entity_mismatches": ["<lista de divergências encontradas>"],
            "key_findings": ["<top 3-5 descobertas>"],
            "search_summary": "<breve descrição das buscas realizadas e resultados>"
          }
          ```

          **Guia de pontuação:**
          - 0-15: Pessoa verificada no LinkedIn/redes sociais, domínio corresponde à org, alegações consistentes
          - 30-50: Alguma presença online mas com lacunas, domínio existe mas informações limitadas
          - 50-75: Alega autoridade mas sem presença online, domínio vazio ou não relacionado, divergências encontradas
          - 75-100: Entidades inexistentes, identidade falsa, impersonação de domínio, credenciais fabricadas

          **Guia de confiança:**
          - 0.9-1.0: Evidências extensas encontradas (múltiplas fontes confirmam/negam)
          - 0.6-0.8: Evidências moderadas (algumas fontes, verificação parcial)
          - 0.3-0.5: Evidências limitadas (poucos resultados, inconclusivo)
          - 0.1-0.2: Dados muito limitados disponíveis

          Responda em português brasileiro. Responda APENAS com o objeto JSON após concluir sua pesquisa.
        PROMPT
      end

      private

      def format_entities
        lines = []

        if @entities[:claimed_entities][:authority_claims].any?
          lines << "### Alegações de Autoridade"
          @entities[:claimed_entities][:authority_claims].each { |c| lines << "- #{c}" }
        end

        if @entities[:claimed_entities][:organizations].any?
          lines << "### Organizações Alegadas"
          @entities[:claimed_entities][:organizations].first(5).each { |o| lines << "- #{o}" }
        end

        if @entities[:claimed_entities][:people].any?
          lines << "### Pessoas Mencionadas"
          @entities[:claimed_entities][:people].first(5).each { |p| lines << "- #{p}" }
        end

        if @entities[:sender][:name].present?
          lines << "### Remetente"
          lines << "- Nome: #{@entities[:sender][:name]}"
          lines << "- E-mail: #{@entities[:sender][:email]}"
          lines << "- Domínio: #{@entities[:sender][:domain]}"
        end

        lines.empty? ? "Nenhuma entidade específica extraída." : lines.join("\n")
      end

      def person_research_instructions
        if @entities[:skip_person_research]
          "2. **Verificação de pessoa**: PULAR (endereço de remetente genérico/automatizado — nenhuma pessoa para verificar)"
        else
          "2. **Verificação de pessoa**: Busque pelo remetente \"#{@email.from_name}\" + \"#{@email.sender_domain}\" — esta pessoa existe nesta organização?"
        end
      end
    end
  end
end
